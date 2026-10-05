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

Phase B (offline usage analysis over the source) is what reachability needs, and it runs whenever the sandbox is
available: it never depends on phase A. Phase A is **opt-in** (`SANDBOX_INSTALL=true`, default `false`) and only
refines phase B: for PyPI it yields the distribution → module mapping read from the installed metadata (merged into
the import names phase B looks for), for npm the installed tree is used to cross-check the lockfile's resolved
versions (`SANDBOX_VERSION_MISMATCH` warning). A failing install (monorepos, private registries, …) only produces a
`SANDBOX_INSTALL_PARTIAL` warning; phase B still runs.

### Phase A: install (`install()`, opt-in)

```
           per-scan  --internal  network (no route out)                   default bridge
 ┌───────────────────────────────┐        ┌──────────────────────┐
 │ vibesec-install-<scan>-<rnd>  │ CONNECT│ vibesec-proxy-...    │──── 443 ───▶ registry.npmjs.org
 │ npm ci --ignore-scripts / pip │───────▶│ allowlist, :3128     │              registry.yarnpkg.com
 │ HTTPS_PROXY=http://proxy:3128 │        │ (also on bridge)     │              pypi.org, files.pythonhosted.org
 └───────────────────────────────┘        └──────────────────────┘
```

* **Where it installs:** into a size-capped tmpfs at `/out` (`--tmpfs /out:…,size=SANDBOX_MAX_DEPS_MB,uid=10001`,
  default 1536 MB), which is the install **disk quota**: a bigger install hits `ENOSPC` and fails with
  `SANDBOX_INSTALL_FAILED` (`installed dependencies exceed … MB`) while it runs, not afterwards. Nothing installed
  ever reaches the host disk; the tmpfs is charged to the container's memory cgroup, so the install container's
  `--memory` is 2 GB plus the quota. Inputs come from `/in` (read-only, staged by the host) and the container
  writes only small result files to `/res`: `tree.json` (npm/pnpm), or pip's `report.json` plus
  `distmap.json` for PyPI. Verified on Docker Desktop 28.5 (tmpfs `size=`/`uid=` honoured).
* **npm:** only `package.json` and the one lockfile that is used are copied into a fresh staging dir (`/in`, then
  copied into `/out/work` by the fixed script).
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

  The tree comes from `npm ls --all --json` (`pnpm ls --json` for pnpm) written to `/res/tree.json`. A non-zero
  exit with JSON output is accepted. The repository checkout itself is **not** mounted during install.
* **PyPI:** the caller converts the lockfile (poetry / uv / Pipfile / requirements) into pinned
  `name==version` lines **on the host**. `install()` takes this `requirements: string[]` instead of a
  manifest dir, so no build backend, `setup.py` or pip config from the repo is ever involved. Each line must be
  a plain PEP 508 requirement. Options (`-r`, `--index-url`, `-e`), URLs, paths and hashes are dropped, each
  with a warning. The install runs a fixed driver staged by the host (`python /in/vibesec_install.py <pip args>`,
  source: `PYPI_INSTALL_DRIVER` in `dockerSandbox.ts`), which calls
  `pip install --isolated --only-binary=:all: --index-url https://pypi.org/simple --proxy … --target /out/deps --report /res/report.json -r /in/requirements.txt`
  and then, still inside the container, maps every installed `*.dist-info` to its top-level modules
  (`top_level.txt`, else the `RECORD` paths; links and files > 4 MB skipped, ≤ 5000 dists × 50 modules) into
  `/res/distmap.json`. The host reads it with the capped no-follow reader and validates every name.
* **Egress:** the per-scan network is created with `--internal`. Its only other member is the proxy container,
  which is also attached to the default bridge, so the proxy is the only way out. Docker's embedded DNS does
  not resolve external names on an internal network (verified: `EAI_AGAIN`). The proxy (`proxy/proxy.mjs`)
  works as follows:
  * It accepts **only** `CONNECT` and refuses every plain-HTTP request (403).
  * It allows only exact, case-insensitive host matches, with no wildcards and no suffix matching.
  * IP literals are always refused.
  * Only port 443 is allowed (80 and everything else get 403).
  * It resolves the allowlisted name itself and refuses non-public answers: RFC 1918, loopback, link-local,
    CGNAT, multicast, `198.18.0.0/15`, `192.0.0.0/24`, and on IPv6 `::`/`::1`, v4-mapped and v4-compatible
    (`::a.b.c.d`) forms of those, NAT64 (`64:ff9b::/96`, `64:ff9b:1::/48`), 6to4 (`2002::/16`), ULA
    (`fc00::/7`), link-local, site-local (`fec0::/10`), documentation and multicast. Unparseable answers are refused.
  * It enforces a per-connection idle timeout (30 s) and at most 64 concurrent connections.
  * It logs every decision as one JSON line. Denied targets come back to the caller as warnings (`sandbox
    proxy denied egress to …`), which is a useful signal on its own (for example, a lockfile pointing at a git
    host).
* **After install:** the host reads the result files (capped, never following links) and deletes the run dir
  through the offline helper container (see below). Nothing of the install is kept.

### Phase B: analyze (`analyze()`)

`--network none`, with these mounts: `/src` (the repo checkout, read-only), `/in/packages.json`
(read-only; `{ ecosystem, packages: [{ name, importNames }] }`) and `/out` (read-write). Installed dependencies
are never mounted: the analyzers only parse the source. The container runs our analyzer (`node /opt/vibesec/analyze.mjs` or
`python /opt/vibesec/analyze.py`), and the host reads `/out/usages.json`, capped at 50 MB.

## Container flags (every container: install, analyze, proxy, helper)

```
docker run --rm --init --pull never --name vibesec-<phase>-<scan8>-<rand6> --label vibesec.scan=<scanId>
  --label vibesec.instance=<instance id> --hostname sandbox --user 10001:10001 --read-only --tmpfs /tmp:rw,noexec,nosuid,nodev,size=256m
  --cap-drop ALL --security-opt no-new-privileges --pids-limit 512 --memory 2g --memory-swap 2g --cpus 2
  --ulimit core=0 --network <internal-net | none | bridge (proxy only)>
  --env K=V ...            # explicit, fixed values only
  --mount type=bind,source=<abs host path>,target=/out[,readonly] ...
  [--tmpfs /out:rw,noexec,nosuid,nodev,size=<quota>,uid=10001,gid=10001,mode=0700]   # phase A only
  [--workdir ...] <prefix>/sandbox-<kind>:v1 <fixed command>
```

* The proxy gets 256 MB, 0.5 CPU and 64 pids. Helpers get 256 MB, 1 CPU and 64 pids. Phase-A installs get
  2 GB + the tmpfs quota of memory.
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
* The phase-A results dir `/res` is created with mode `1777` (sticky), so uid 10001 can add result files but
  cannot replace host-made entries.
* Every container and network also carries `vibesec.instance=<id>`: the API instance's id, a UUID persisted in
  `<WORK_DIR>/sandbox-instance.id` (stable across restarts). `sweep(scanId)` removes this instance's containers,
  networks and volumes labeled `vibesec.scan=<scanId>`, plus the scan's staging dir (via the helper).
  `sweep()` with no argument (on startup) removes **this instance's** leftovers only, so several API instances
  can share one Docker daemon without sweeping each other's running scans.

## Fallback

`availability()` runs `docker version` plus `docker image inspect` of the three images, with the result cached
for 30 s. **Docker Engine ≥ 26 is required**: before 26, containers on an `--internal` network could still resolve
names through the embedded DNS forwarding to external resolvers (CVE-2024-29018), a DNS exfiltration channel out
of phase A; older engines report `SANDBOX_UNAVAILABLE`. When Docker or the images are missing, the network cannot be created, or the daemon refuses a
container (exit 125), the result is `{ ok: false, code: 'SANDBOX_UNAVAILABLE' }`. The caller then falls back to
lockfile-only analysis and records the `SANDBOX_UNAVAILABLE` warning. `SANDBOX_ENABLED=false` disables the
sandbox entirely; that check is the caller's responsibility.

## What is NOT isolated (known limits)

* **Kernel:** containers share the host kernel (runc plus Docker's default seccomp and AppArmor profiles). A
  kernel exploit escapes. **In production, run the sandbox under gVisor (`--runtime runsc`) or in
  Firecracker / Kata microVMs**, on dedicated nodes with no cloud credentials.
* **Registry content:** the allowlist stops exfiltration to arbitrary hosts, but a malicious package can still
  be *downloaded*, and data could in principle be encoded into requests to the allowlisted registries
  (package-name lookups). This is acceptable because no attacker code runs in phase A. The same holds for
  domain fronting through the allowlisted CDNs (the proxy checks the CONNECT host, not the TLS SNI / HTTP Host
  inside the tunnel): only the package manager speaks through the tunnel.
* **Phase B** executes no attacker code, only our analyzer *parsing* attacker files. A parser bug is contained
  by `--network none`, the read-only mounts and the resource limits.
* **Disk:** phase A writes into the size-capped tmpfs (memory-backed), so the quota is enforced during the
  install; the host only receives the small result files (≤ 50 MB tree, ≤ 8 MB module map).
* **pnpm and yarn workspaces / monorepos, private registries:** only the one manifest dir is staged and only the
  public registries are reachable, so such installs fail (`SANDBOX_INSTALL_FAILED`). That only loses the phase-A
  refinements; phase B is unaffected.
* **Docker Desktop (Windows / macOS):**
  * Bind-mount I/O is slow (phase A now installs into a tmpfs, so only the inputs/results cross it). Container
    start takes 1–4 s and the cleanup helper about 2–10 s.
  * Container-made symlinks are opaque to Windows (see above).
  * Paths are passed as absolute Windows paths in `--mount source=` (verified on Docker Desktop 28.5).
* **Linux hosts:** host dirs handed to the container are `chmod 0777` / `1777` so uid 10001 can write them.
  Keep `WORK_DIR` private (mode 700) to other host users.
