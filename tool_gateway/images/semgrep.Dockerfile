# The image the Semgrep tool runs in (D43).
#
# A Dockerfile, not the docker-import scratch route the nmap/http images use
# (_python_scratch.sh) -- the same reason the browser image (D36) is one:
# Semgrep is a Python application with its own dependency tree (60+ packages
# at pin time), not a single binary `ldd` can enumerate the closure of.
#
# No network egress is configured for this container at all, deliberately
# (D43-5 Option B, docs/ADR_SEMGREP.md §3.1): the repository this scans is
# fetched by the control plane, outside any sandbox, and handed in read-only
# via DockerSandbox's ``source_mount``. This container never holds a git
# credential and is never given a route to fetch one on its own -- unlike
# nmap/curl/the browser, which all reach a target over the network this
# image is expressly not given.
#
# The scanning ruleset is likewise not fetched at run time from Semgrep's
# registry: --config points at a local file mounted in alongside the
# repository, the same way the repository itself arrives, so a rule-pack
# fetch is never a network operation this container performs.

ARG BASE=python:3.12-slim
FROM ${BASE}

ARG SEMGREP_VERSION=1.178.0

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    SEMGREP_SEND_METRICS=off

RUN pip install --no-cache-dir "semgrep==${SEMGREP_VERSION}" \
    && semgrep --version

# Record provenance the same way the browser image does (D36): what exactly
# is in here, not just "semgrep, latest".
RUN mkdir -p /etc/cyberorch \
    && { echo "semgrep_version=${SEMGREP_VERSION}"; \
         echo "base_image=${BASE}"; \
         echo "built_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"; } \
       > /etc/cyberorch/semgrep-manifest.txt

# A user that owns nothing sensitive, same reasoning as the browser image:
# the container holds no secret to begin with (no credential, no network),
# but running as a real tool's own uid rather than the image default is
# cheap belt-and-braces.
RUN useradd --system --uid 10001 --create-home --home-dir /home/semgrep semgrep
USER semgrep
WORKDIR /home/semgrep

# semgrep writes a settings file and a log under $HOME on every run
# (confirmed empirically: ~/.semgrep/settings.yml, ~/.semgrep/semgrep.log) --
# this needs the tmpfs the sandbox mounts at run time (D36's precedent),
# not a workaround baked into the image.
ENTRYPOINT ["/usr/local/bin/semgrep"]
