# vibesec/sandbox-proxy — the egress allowlist proxy for phase A (see proxy.mjs). No dependencies.
# Build context: sandbox/proxy/  (built by `npm run sandbox:build`).
FROM node:22.23.3-alpine3.24@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402

RUN rm -f /usr/local/bin/yarn /usr/local/bin/yarnpkg && rm -rf /opt/yarn-v* \
 && addgroup -g 10001 sandbox && adduser -D -H -u 10001 -G sandbox -s /sbin/nologin sandbox
COPY proxy.mjs /opt/vibesec/proxy.mjs
RUN chmod -R a+rX /opt/vibesec

ENV PROXY_PORT=3128 \
    PROXY_ALLOW=registry.npmjs.org,registry.yarnpkg.com,pypi.org,files.pythonhosted.org \
    PROXY_ALLOW_PORTS=443
USER 10001:10001
EXPOSE 3128
CMD ["node", "/opt/vibesec/proxy.mjs"]
