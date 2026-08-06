ARG BASE_IMAGE=docker.io/daytonaio/sandbox:0.6.0-slim@sha256:825533a16c854304facdff594bc1a0ff3eb223a25c2ff9b1b70b5e05fb754492
FROM ${BASE_IMAGE}

# Ambit treats /workspace as the provider-independent writable root for agent
# runs, MCP runtime bundles, checkpoints, media, and artifacts.  Satisfy that
# contract in the admitted image instead of teaching runtime code about a
# Daytona-specific home directory.
USER root
RUN install -d -m 0755 -o daytona -g daytona /workspace

USER daytona
WORKDIR /workspace
RUN test -w /workspace
