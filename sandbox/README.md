# VibeSec dependency sandbox

The dependency analyzer has to **install** and **statically analyze** the dependencies of attacker-controlled
repositories. Both steps run in throw-away Docker containers driven by
`apps/api/src/sandbox/dockerSandbox.ts` (`DockerSandbox`). The repository being scanned is treated as hostile
in every step, as is everything it pulls from the registries.

```
npm run sandbox:build      # builds vibesec/sandbox-{node,python,proxy}:v1 (SANDBOX_IMAGE_PREFIX overrides "vibesec")
```

| Image | Base (pinned tag + index digest) | Contents |
|---|---|---|
| `sandbox-node` | `node:22.23.3-alpine3.24` | npm 10.9.9 (bundled), corepack with pnpm 10.34.6, yarn 1.22.22 and yarn 4.18.1 pre-fetched, `typescript@5.9.3` in `/opt/vibesec/node_modules`, analyzer `/opt/vibesec/analyze.mjs` |
| `sandbox-python` | `python:3.12.15-slim-trixie` | pip 25.0.1 (bundled), analyzer `/opt/vibesec/analyze.py` (stdlib only) |
| `sandbox-proxy` | `node:22.23.3-alpine3.24` | `proxy.mjs`: the egress allowlist proxy (no dependencies) |

The Dockerfiles copy the whole `sandbox/<eco>/` directory, so they build even before the analyzer scripts exist.
Versions are `ARG`s in `sandbox/node/Dockerfile`. The pnpm and yarn versions must match the constants in
`dockerSandbox.ts`.

## Threat model

**Attacker:** whoever controls the scanned repository. They control `package.json`, the lockfiles, requirement
pins, source files, and any package they publish to npm or PyPI and reference from the lockfile. That includes
install scripts, `bin` entries, symlinks inside tarballs, huge or deeply nested trees, and file names.

**Assets:** host credentials (`GITHUB_TOKEN`, `ANTHROPIC_API_KEY`, cloud and registry tokens, the operator's
`~/.npmrc` and `~/.docker/config.json`), the host filesystem, the internal network or cloud metadata endpoint,
other scans, and the availability of the service.

**Goals:**

1. No attacker code runs during install. Lifecycle scripts are off, and only wheels are installed, so there are
   no sdist builds.
2. Even if code does run (a package-manager bug, or a malicious analyzer input exploiting the analyzer), it has
   no credentials, no network except the registry allowlist (phase A) or none at all (phase B), no writable root
   filesystem, no capabilities, bounded resources, and a hard deadline.
3. Nothing the container writes is ever trusted or followed on the host.

## Two phases

### Phase A: install (`install()`)

```
           per-scan  --internal  network (no route out)                   default bridge
 ┌───────────────────────────────┐        ┌──────────────────────┐
 │ vibesec-install-<scan>-<rnd>  │ CONNECT│ vibesec-proxy-...    │──── 443 ───▶ registry.npmjs.org
 │ npm ci --ignore-scripts / pip │───────▶│ allowlist, :3128     │              registry.yarnpkg.com
 │ HTTPS_PROXY=http://proxy:3128 │        │ (also on bridge)     │              pypi.org, files.pythonhosted.org
 └───────────────────────────────┘        └──────────────────────┘
```

* **npm:** only `package.json` and the one lockfile that is used are copied into a fresh staging dir.
  `.npmrc`, `.yarnrc(.yml)` and `pnpm-workspace.yaml` are **never** copied, because they can carry tokens,
  alternate registries, `yarnPath` (arbitrary JS) or plugins. The repo's `packageManager` field is replaced by
  our pinned version: corepack runs with `COREPACK_ENABLE_NETWORK=0` and the versions baked into the image.
  The commands, chosen by lockfile:
  * `package-lock.json` / `npm-shrinkwrap.json`: `npm ci --ignore-scripts`
  * `pnpm-lock.yaml`: `pnpm install --frozen-lockfile --ignore-scripts`
  * yarn v1 lockfile: `yarn install --frozen-lockfile --ignore-scripts`
  * yarn berry lockfile: `yarn install --immutable --mode=skip-build`, with `YARN_ENABLE_SCRIPTS=false` and
    `nodeLinker=node-modules`
  * no lockfile: `npm install --package-lock-only --ignore-scripts`, then `npm ci`

  The tree comes from `npm ls --all --json` (`pnpm ls --json` for pnpm). A non-zero exit with JSON output is
  accepted. The repository checkout itself is **not** mounted during install.
* **PyPI:** the caller converts the lockfile (poetry / uv / Pipfile / requirements) into pinned
  `name==version` lines **on the host**. `install()` takes this `requirements: string[]` instead of a
  manifest dir, so no build backend, `setup.py` or pip config from the repo is ever involved. Each line must be
  a plain PEP 508 requirement. Options (`-r`, `--index-url`, `-e`), URLs, paths and hashes are dropped, each
  with a warning. The install runs
  `pip install --isolated --only-binary=:all: --index-url https://pypi.org/simple --proxy … --target /out/deps --report /out/report.json -r /in/requirements.txt`.
* **Egress:** the per-scan network is created with `--internal`. Its only other member is the proxy container,
  which is also attached to the default bridge, so the proxy is the only way out. Docker's embedded DNS does
  not resolve external names on an internal network (verified: `EAI_AGAIN`). The proxy (`proxy/proxy.mjs`)
  works as follows:
  * It accepts **only** `CONNECT` and refuses every plain-HTTP request (403).
  * It allows only exact, case-insensitive host matches, with no wildcards and no suffix matching.
  * IP literals are always refused.
  * Only port 443 is allowed (80 and everything else get 403).
  * It resolves the allowlisted name itself and refuses private, loopback, link-local or multicast answers.
  * It enforces a per-connection idle timeout (30 s) and at most 64 concurrent connections.
  * It logs every decision as one JSON line. Denied targets come back to the caller as warnings (`sandbox
    proxy denied egress to …`), which is a useful signal on its own (for example, a lockfile pointing at a git
    host).
* **After install:** an offline helper container (see below) removes caches and reports the size with `du`.
  Installs larger than `SANDBOX_MAX_DEPS_MB` (default 1536) fail and are deleted. The host then checks that
  every path component down to the deps dir is a real directory, not a link.

### Phase B: analyze (`analyze()`)

`--network none`, with these mounts: `/src` (the repo checkout, read-only), `/deps` (the phase-A deps dir,
read-only, and only if it is under this scan's sandbox dir with no link components), `/in/packages.json`
(read-only) and `/out` (read-write). The container runs our analyzer (`node /opt/vibesec/analyze.mjs` or
`python /opt/vibesec/analyze.py`), and the host reads `/out/usages.json`, capped at 50 MB.

## Container flags (every container: install, analyze, proxy, helper)

```
docker run --rm --init --pull never --name vibesec-<phase>-<scan8>-<rand6> --label vibesec.scan=<scanId>
  --hostname sandbox --user 10001:10001 --read-only --tmpfs /tmp:rw,noexec,nosuid,nodev,size=256m
  --cap-drop ALL --security-opt no-new-privileges --pids-limit 512 --memory 2g --memory-swap 2g --cpus 2
  --ulimit core=0 --network <internal-net | none | bridge (proxy only)>
  --env K=V ...            # explicit, fixed values only
  --mount type=bind,source=<abs host path>,target=/out[,readonly] ...
  [--workdir ...] <prefix>/sandbox-<kind>:v1 <fixed command>
```

* The proxy gets 256 MB, 0.5 CPU and 64 pids. Helpers get 256 MB, 1 CPU and 64 pids.
* No `--privileged`, no added capabilities, no devices, no host namespaces, and no Docker socket.
* `--pull never`: only locally built images ever run.
* **Deadlines:** 180 s for install (`SANDBOX_INSTALL_TIMEOUT_MS`) and 120 s for analyze
  (`SANDBOX_ANALYZE_TIMEOUT_MS`). These are enforced by `runProcess`, and on expiry or cancellation the
  container itself is stopped with `docker kill <name>` followed by `docker rm -f`. Killing the docker CLI alone
  would leave the container running. Cancellation (`AbortSignal`) throws `AppError('CANCELLED', 'cancelled')`
  after cleanup, like the rest of the codebase.
* **The docker CLI's own environment is an allowlist:** `PATH`, `SystemRoot`, `DOCKER_HOST`,
  `DOCKER_CONTEXT`, `DOCKER_CONFIG`, `DOCKER_CERT_PATH`, `DOCKER_TLS_VERIFY`, `USERPROFILE`, `HOME`, `TEMP`
  and `TMP`. Containers receive only the explicit `--env` values: no tokens and no host env.
* No attacker-controlled string is ever interpolated into a shell command. Install scripts are constants, and
  repo content reaches the container only as files.

## Host-side hygiene

* Manifest files are copied only if `lstat` says they are regular files (≤ 50 MB). The manifest dir must
  `realpath` inside the checkout.
* Container output (`tree.json`, `report.json`, `usages.json`) is read with `lstat`, then `open(O_NOFOLLOW)`,
  then `fstat`, with a size cap. Symlinks, special files and unreadable entries are refused.
* **The host never traverses or deletes container-written trees.** They may contain links to host paths,
  mode-000 directories, files owned by uid 10001 (on Linux the host user cannot delete them), and, on Docker
  Desktop for Windows, Linux symlinks that show up as unreadable reparse points on which Node's `fs.rm` **hangs
  forever** (observed with a pnpm `node_modules`). Instead, deletion and size measurement run in an offline
  *helper* container (`sandbox-node`, `--network none`, the same hardening) over the directory mounted at `/w`.
  The host then removes only the emptied, host-owned directories. If the helper cannot run, the directory is
  left for the next sweep.
* `/out` is created with mode `1777` (sticky), so uid 10001 can add entries but cannot replace the host-made
  `work`, `cache` and `tmp` dirs.
* `sweep(scanId)` removes containers, networks and volumes labeled `vibesec.scan=<scanId>`, plus the scan's
  staging dir (via the helper). `sweep()` with no argument removes **all** labeled leftovers. Call it on startup
  only when no other process is running scans against the same Docker daemon.

## Fallback

`availability()` runs `docker version` plus `docker image inspect` of the three images, with the result cached
for 30 s. When Docker or the images are missing, the network cannot be created, or the daemon refuses a
container (exit 125), the result is `{ ok: false, code: 'SANDBOX_UNAVAILABLE' }`. The caller then falls back to
lockfile-only analysis and records the `SANDBOX_UNAVAILABLE` warning. `SANDBOX_ENABLED=false` disables the
sandbox entirely; that check is the caller's responsibility.

## What is NOT isolated (known limits)

* **Kernel:** containers share the host kernel (runc plus Docker's default seccomp and AppArmor profiles). A
  kernel exploit escapes. **In production, run the sandbox under gVisor (`--runtime runsc`) or in
  Firecracker / Kata microVMs**, on dedicated nodes with no cloud credentials.
* **Registry content:** the allowlist stops exfiltration to arbitrary hosts, but a malicious package can still
  be *downloaded*, and data could in principle be encoded into requests to the allowlisted registries
  (package-name lookups). This is acceptable because no attacker code runs in phase A.
* **Phase B** executes no attacker code, only our analyzer *parsing* attacker files. A parser bug is contained
  by `--network none`, the read-only mounts and the resource limits.
* **Disk:** the size cap is checked *after* install. During install, writes are bounded only by the deadline
  and the host disk, so put `WORK_DIR` on a quota'd volume in production.
* **pnpm and yarn workspaces / monorepos:** only the one manifest dir is staged, so workspace installs fail
  (`SANDBOX_INSTALL_FAILED`) and the caller falls back.
* **Docker Desktop (Windows / macOS):**
  * Bind-mount I/O is slow. A one-package npm install takes about 20–60 s end to end, the helper `du` and
    `rm` about 2–10 s, and container start 1–4 s.
  * Container-made symlinks are opaque to Windows (see above).
  * Paths are passed as absolute Windows paths in `--mount source=` (verified on Docker Desktop 28.5).
* **Linux hosts:** host dirs handed to the container are `chmod 0777` / `1777` so uid 10001 can write them.
  Keep `WORK_DIR` private (mode 700) to other host users.
