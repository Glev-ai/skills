# Minimal opengrep image used by the glev-application-security-trend-report skill.
# Built automatically by scripts/lib/opengrep.py on first run if not cached.
#
# OpenGrep doesn't publish an anonymously-pullable image, but it does ship
# precompiled binaries on GitHub Releases. We wrap the binary in a slim
# Debian image so the skill can drive it via `docker run` like any other
# scanner image.

# The opengrep release we download is `opengrep_manylinux_x86` -- x86_64
# only. Pinning the platform via an ARG (rather than a literal in FROM)
# avoids buildkit's "FromPlatformFlagConstDisallowed" warning while keeping
# the build deterministic across hosts (Apple Silicon, etc.).
ARG IMAGE_PLATFORM=linux/amd64
FROM --platform=${IMAGE_PLATFORM} debian:bookworm-slim

# OpenGrep v1.16.4+ requires UTF-8 locale for rule loading.
ENV LANG=C.UTF-8

ARG OPENGREP_VERSION=v1.16.5

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fL \
    -o /usr/local/bin/opengrep \
    "https://github.com/opengrep/opengrep/releases/download/${OPENGREP_VERSION}/opengrep_manylinux_x86" \
    && chmod +x /usr/local/bin/opengrep

WORKDIR /src
ENTRYPOINT ["opengrep"]
