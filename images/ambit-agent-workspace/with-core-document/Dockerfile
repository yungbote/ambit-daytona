# Frontier toolchain image (daytona repo revision 61d2cd1b) plus the certified
# ambit-atomic-materialize helper layer the runtime evidence binds, byte-exact
# from the currently admitted snapshot.
FROM us-east4-docker.pkg.dev/mwcc-infrastructure/ambit/ambit-agent-workspace:polyglot-docs5-20260903 AS helper
FROM us-east4-docker.pkg.dev/mwcc-infrastructure/ambit/ambit-agent-workspace:main-61d2cd1b-toolchains
USER root
COPY --from=helper /opt/ambit/runtime-pack /opt/ambit/runtime-pack
RUN test -x /opt/ambit/runtime-pack/core-document/bin/ambit-atomic-materialize
USER daytona
WORKDIR /workspace
