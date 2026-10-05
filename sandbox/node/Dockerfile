# vibesec/sandbox-node — phase A (npm/pnpm/yarn install, scripts disabled) and phase B (offline usage analysis).
# Build context: sandbox/node/  (built by `npm run sandbox:build`).
# Base pinned by exact tag AND multi-arch index digest; npm 10.9.9 is the version bundled with this node.
FROM node:22.23.3-alpine3.24@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402

# Must match PNPM_VERSION / YARN_*_VERSION in apps/api/src/sandbox/dockerSandbox.ts.
ARG PNPM_VERSION=10.34.6
ARG YARN_CLASSIC_VERSION=1.22.22
ARG YARN_BERRY_VERSION=4.18.1
ARG TYPESCRIPT_VERSION=5.9.3

ENV COREPACK_HOME=/opt/corepack \
    COREPACK_ENABLE_DOWNLOAD_PROMPT=0 \
    COREPACK_ENABLE_AUTO_PIN=0 \
    NPM_CONFIG_UPDATE_NOTIFIER=false \
    NPM_CONFIG_FUND=false \
    NPM_CONFIG_AUDIT=false

# The image's bundled yarn classic is replaced by corepack shims; all package-manager versions are fetched NOW
# (build time) so the sandbox can run corepack with COREPACK_ENABLE_NETWORK=0.
RUN rm -f /usr/local/bin/yarn /usr/local/bin/yarnpkg \
 && rm -rf /opt/yarn-v* \
 && corepack enable --install-directory /usr/local/bin pnpm yarn \
 && corepack install -g "pnpm@${PNPM_VERSION}" \
 && corepack install -g "yarn@${YARN_BERRY_VERSION}" \
 && corepack install -g "yarn@${YARN_CLASSIC_VERSION}" \
 && chmod -R a+rX "${COREPACK_HOME}" \
 && addgroup -g 10001 sandbox \
 && adduser -D -H -u 10001 -G sandbox -s /sbin/nologin sandbox

# Analyzer runtime: typescript (pinned) lives next to the analyzer under /opt/vibesec, never under /src.
WORKDIR /opt/vibesec
RUN npm install --no-audit --no-fund --ignore-scripts --omit=dev --no-save "typescript@${TYPESCRIPT_VERSION}" \
 && npm cache clean --force \
 && rm -rf /root/.npm

# The analyzer script (sandbox/node/analyze.mjs) and anything beside it. Copying the directory (not the single
# file) keeps the image buildable while the script is being developed.
COPY . /opt/vibesec/
RUN rm -f /opt/vibesec/Dockerfile && chmod -R a+rX /opt/vibesec

ENV COREPACK_ENABLE_NETWORK=0 \
    HOME=/tmp
USER 10001:10001
WORKDIR /tmp
CMD ["node", "/opt/vibesec/analyze.mjs"]
