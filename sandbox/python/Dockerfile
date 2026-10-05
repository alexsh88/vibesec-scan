# vibesec/sandbox-python — phase A (pip install, binary wheels only) and phase B (offline usage analysis).
# Build context: sandbox/python/  (built by `npm run sandbox:build`).
# Base pinned by exact tag AND multi-arch index digest; pip 25.0.1 is the version bundled with this python.
FROM python:3.12.15-slim-trixie@sha256:02108f5d322dd89f1c9e552442c25acb0543dfdbc455693a5599624f20d9155d

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

RUN groupadd -g 10001 sandbox \
 && useradd -u 10001 -g 10001 -M -d /tmp -s /usr/sbin/nologin sandbox

# The analyzer script (sandbox/python/analyze.py, stdlib only) and anything beside it. Copying the directory
# (not the single file) keeps the image buildable while the script is being developed.
COPY . /opt/vibesec/
RUN rm -f /opt/vibesec/Dockerfile && chmod -R a+rX /opt/vibesec

ENV HOME=/tmp
USER 10001:10001
WORKDIR /tmp
CMD ["python", "/opt/vibesec/analyze.py"]
