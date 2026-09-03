# ambit-agent-workspace + certified core-document pack

The runtime evidence bundle binds a full image that carries the certified
`ambit-atomic-materialize` helper at
`/opt/ambit/runtime-pack/core-document/bin/ambit-atomic-materialize`
(sha256 d6d8bd42…; the Daytona runner and the evidence CLI both check it).
The toolchain image alone does not carry it. This Dockerfile lays the
`/opt/ambit/runtime-pack` tree from the last admitted snapshot on top of the
toolchain image; the composed digest is what gets registered as the snapshot
and named in the evidence bundle (`--snapshot`).

Built 2026-09-03 as `frontier-61d2cd1b-helper` →
`sha256:1dbc9cac4326224679f4bae44402839f1c3c064db2bc2c34d62782aad625c950`,
Daytona snapshot 5a231300 (cpu 2 / mem 4 / disk 10, the admitted sizes).
