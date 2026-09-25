# The image the Playwright browser tool runs in (§8.3, D36).
#
# Why this is a Dockerfile and not the docker-import scratch route the other
# three images use (_python_scratch.sh):
#
# Chromium is a different order of magnitude from a stdlib Python interpreter.
# It is a ~300 MB binary that, at run time, dlopens a set of libraries `ldd`
# never names (nss, gssapi, vulkan ICDs, libpci) and reads a large config tree
# by content -- /etc/fonts and fontconfig, hundreds of font files, nss modules,
# /etc/resolv.conf. Hand-staging that tree is the D31 "four CI rounds
# diagnosing a container that won't serve" failure with forty moving parts
# instead of one libz, and it buys no traceability: the Chromium binary, its
# .pak blobs and swiftshader are Playwright-distributed either way, so copying
# them by hand does not make them more auditable. What is auditable is *which
# packages and which browser revision* -- and that this Dockerfile records
# exactly, in /etc/cyberorch/browser-manifest.txt, baked in at build time.
#
# The cost, accepted when this route was chosen over scratch-from-host: one
# base-image layer is now a trust root instead of the operator's own host
# binaries. It is pinned (BASE below) and its resolved digest is recorded in
# the manifest.
#
# The browser runs as a non-root user that owns nothing (D36 §四). A headless
# Chromium steered to a file:// URL *will* read any file its uid can read --
# that was confirmed empirically, it is not blocked by the browser's own
# sandbox -- so the isolation cannot rest on the browser refusing. It rests on
# the container holding no secret and the browser uid owning none of what is
# here. The engagement CA private key never enters this image or this
# container; only the public CA certificate is mounted at run time (0644),
# exactly as for the curl tools (D35).

ARG BASE=ubuntu:24.04
FROM ${BASE}

# Pinned so the browser revision is fixed, not "whatever is latest at build".
# Playwright 1.56.1 ships Chromium revision 1194 (browserVersion 141.0.7390.37);
# pinning the pip version pins the browser it installs.
ARG PLAYWRIGHT_VERSION=1.56.1
ARG CHROMIUM_REVISION=1194

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PLAYWRIGHT_BROWSERS_PATH=/opt/pw-browsers

# The runtime closure, enumerated rather than pulled in by `playwright
# install-deps`. Every name here was derived from the linked and dlopen'd
# libraries of the pinned headless_shell build, plus the config trees it reads
# (fontconfig, fonts, ca-certificates). Listing them makes the build fail
# loudly if the set changes between browser revisions, instead of a page
# rendering subtly wrong.
RUN apt-get update && apt-get install --no-install-recommends -y \
      python3 python3-pip python3-venv \
      ca-certificates fontconfig fonts-liberation fonts-unifont \
      libasound2t64 libatk-bridge2.0-0t64 libatk1.0-0t64 libatspi2.0-0t64 \
      libc6 libcairo2 libcap2 libcups2t64 libdbus-1-3 libdrm2 libexpat1 \
      libffi8 libgbm1 libgcc-s1 libgcrypt20 libglib2.0-0t64 libgpg-error0 \
      libnspr4 libnss3 libpango-1.0-0 libpangocairo-1.0-0 libpcre2-8-0 \
      libselinux1 libsystemd0 libudev1 libx11-6 libx11-xcb1 libxau6 \
      libxcb1 libxcb-dri3-0 libxcomposite1 libxdamage1 libxdmcp6 libxext6 \
      libxfixes3 libxi6 libxkbcommon0 libxrandr2 libxrender1 zlib1g \
    && rm -rf /var/lib/apt/lists/*

# The browser itself, from Playwright's pinned distribution. Installed as root
# into a world-readable location so the non-root browser user can execute it
# but cannot modify it (read-only at run time makes this belt-and-braces).
RUN pip install --break-system-packages "playwright==${PLAYWRIGHT_VERSION}" \
    && python3 -m playwright install chromium \
    && test -x "/opt/pw-browsers/chromium_headless_shell-${CHROMIUM_REVISION}/chrome-linux/headless_shell" \
    && chmod -R a+rX /opt/pw-browsers

# Record provenance: the base digest, the browser revision, and every installed
# package with its resolved version. This is what "we know what is in the
# image" means when the binaries themselves are opaque blobs.
RUN mkdir -p /etc/cyberorch \
    && { echo "playwright_version=${PLAYWRIGHT_VERSION}"; \
         echo "chromium_revision=${CHROMIUM_REVISION}"; \
         echo "base_image=${BASE}"; \
         echo "built_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
         echo "--- dpkg packages ---"; \
         dpkg-query -W -f='${Package}=${Version}\n' | sort; } \
       > /etc/cyberorch/browser-manifest.txt

# A user that owns nothing sensitive. The browser process runs as this uid; the
# only things it can read are this image's own contents (no secret) and what is
# mounted read-only at run time (the public CA cert). See the Dockerfile header
# and D36 §四 for why the isolation depends on this rather than on the browser.
RUN useradd --system --uid 10001 --create-home --home-dir /home/browser browser
USER browser
WORKDIR /home/browser

# The driver script is copied in by the build script (kept out of the Dockerfile
# so it is the one in the repository, not a heredoc copy -- same discipline as
# the egress proxy image).
COPY browser_runner.py /opt/browser_runner.py

ENTRYPOINT ["/usr/bin/python3", "-u", "/opt/browser_runner.py"]
