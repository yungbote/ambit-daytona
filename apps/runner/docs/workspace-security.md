# Ordinary workspace security

`WORKSPACE_SECURITY_PROFILE` belongs to the existing Runner Docker configuration owner. Its default, `legacy`, preserves current behavior. `restricted-v1` is an explicit fleet deployment choice; an unknown value prevents Runner initialization before Docker mutations.

The restricted profile applies one coherent configuration after runtime-specific construction:

- Nonprivileged container, all capabilities dropped, no-new-privileges.
- The exact embedded rootless Chromium-compatible seccomp policy, SHA-256 `9de0b08286e0c0ba068eb8f6bf9e2aa49860327b654b8f0b20bcabc4fdc796f2`.
- Private PID, IPC and cgroup namespaces. Explicit host networking or shared namespaces are incompatible.
- Existing image-selected user, writable filesystem, mounts, resource allocations, device assignments, runtime selection and non-host network policy remain owned by their current mechanisms.

This is a container restriction profile. It does not force the image to select a nonroot user, prove VM isolation, change the privileged outer Runner, or certify every device/runtime configuration. User-owned Python/Node environments and downloaded executables remain writable. Sudo, system package operations and nested container workflows that require capabilities need an appropriate separately qualified execution boundary; there is no privileged fallback.

Creation and recreation apply the same profile after runtime-specific overrides. A failed readback removes only the exact container created by that attempt; a conflict-adopted container is never deleted by this path. Cleanup continues with a bounded context after request cancellation, and a removal failure remains explicit with the retained container identity. GPU allocation remains reserved by the container label until removal succeeds. Recreation retains the original until the replacement passes inspection and restores the original on rejection. Docker configuration is inspected before accepting a created container and before starting or converting an existing container. An incompatible existing workspace is rejected; it is not silently relabeled or migrated. Deletion and other cleanup remain available.

Before a running workspace reaches the existing network/proxy readiness gate, admission checks Docker's actual configuration and the container-init process's effective, permitted, bounding, inheritable and ambient capability sets, no-new-privileges and seccomp mode. Linux process start ticks bracket the status observation and are checked again after a second Docker inspection confirms the same running container identity, PID and Docker start timestamp. Missing process visibility or changed identity rejects admission. These observations require the Runner to see the Docker-reported PID in its `/proc`; deployments without that visibility must not advertise this profile. Labels are diagnostic only.

The shared `sandboxsecurity` package contains the seccomp bytes and Linux observation parser. Ordinary and specialist renderers retain separate policies; the specialist's network-none, read-only-root and no-exec scratch restrictions are not imposed on ordinary workspaces. A source test checks that the embedded seccomp bytes match the existing specialist image policy.

## Qualification and rollout

The source unit checks exercise legacy preservation, all unsafe configuration fields, unknown configuration, incompatible existing workspace start without mutation, runtime conversion, capability sets and exact seccomp bytes. An opt-in local Docker test creates and removes only its own container:

```sh
AMBIT_WORKSPACE_SECURITY_DOCKER_TEST_IMAGE=<qualified-local-image> \
  go test ./apps/runner/pkg/docker -run '^TestRestrictedWorkspaceAgainstRealDocker$' -count=1 -v
```

The local browser image based on source `94300bd3aa19fb379c20372dcd3347046392173a` passed that Docker/kernel readback. Browser conformance separately proves renderer sandbox startup, interaction, screenshots, downloads, proxy/CA handling and whole-PID-namespace return to baseline after close and termination with the same security tuple. These results do not establish production Runner compatibility.

Deploy first to a drained canary Runner under the existing allocation/lifecycle owners. Retain the legacy pool and its active or retained workspaces until their work is settled and their portable working copy is captured for replacement; changing the selector on a populated pool can strand incompatible workspaces at the start gate. Keep an explicit rollback to the legacy Runner deployment. Replacing an old workspace follows the current workspace lifecycle; do not flip a populated fleet and assume old containers become restricted. From a fresh owned ordinary Run, verify daemon startup and command execution, file materialization, task-private dependencies, document tools, browser startup and cancellation, effective resource limits, supported network modes and actual process cleanup. Keep successful readback and source/image identities as evidence before broader activation. GPU, Android, Kata/VM and special devices require their own applicable conformance; preserving their settings is not a qualification claim.

Normal Run completion still requires pending processes to be settled through their existing owner. Browser work closes the daemon and observes its tracked process, or cancels that process. This source change does not fix Daytona session deletion's separate failure/escaped-descendant accounting or create an implicit close-on-completion hook.
