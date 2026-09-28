# The image ad.collect (bloodhound-python) runs in (D42/D45).
#
# A Dockerfile, not the docker-import scratch route the nmap/http images use
# -- the same reason the Semgrep (D43) and browser (D36) images are one:
# bloodhound-python is a Python application with its own dependency tree
# (impacket, ldap3, dnspython, pyOpenSSL, ...), not a single binary `ldd`
# can enumerate the closure of.
#
# Unlike Semgrep, this container DOES need network egress -- an LDAP bind
# against a real domain controller is the entire point of ad.collect. The
# sandbox's own CIDR allowlist (§8.3), not this image, is what confines
# where that egress can go; nothing here relaxes it.
#
# The credential this container is handed (D44's mount_for_run) arrives
# exactly like every other mounted secret in this system: a read-only
# bind-mounted file, world-readable (0644) so a non-root container user can
# read it regardless of which host uid wrote it -- the same fix D43's
# git_fetch.fetch_repo needed for its own non-root container user
# (semgrep.Dockerfile), applied here before anyone had to rediscover it
# against this image specifically (D45).

ARG BASE=python:3.12-slim
FROM ${BASE}

ARG BLOODHOUND_VERSION=1.9.0

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN pip install --no-cache-dir "bloodhound==${BLOODHOUND_VERSION}" \
    && bloodhound-python --help >/dev/null

# Provenance, matching every other image built this way (D36/D43).
RUN mkdir -p /etc/cyberorch \
    && { echo "bloodhound_version=${BLOODHOUND_VERSION}"; \
         echo "base_image=${BASE}"; \
         echo "built_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"; } \
       > /etc/cyberorch/bloodhound-manifest.txt

# A user that owns nothing sensitive -- same reasoning as every other image
# here: cheap belt-and-braces even though this container's actual secret
# (the mounted credential file) is protected by its own permissions, not by
# who owns the container's filesystem.
RUN useradd --system --uid 10002 --create-home --home-dir /home/collector collector
USER collector
WORKDIR /home/collector

# No ENTRYPOINT, deliberately -- ad_collector.py's build_plan constructs a
# full, self-contained argv (either bloodhound-python's own absolute path,
# or a /bin/sh -c wrapper) and expects DockerSandbox.run's `command` to be
# the *entire* thing the container executes, unprefixed. semgrep.Dockerfile
# sets an ENTRYPOINT and gets away with a redundant leading argument only
# because semgrep's own CLI happens to tolerate it (confirmed empirically
# while building this image, not assumed) -- bloodhound-python's shell
# wrapper would not survive the same treatment (`sh /usr/bin/bloodhound-
# python ...` would try to interpret a Python script as shell), so this
# image does not repeat that shape.
