#!/usr/bin/bash -p
set -euo pipefail
umask 077
unset BASH_ENV ENV CDPATH GLOBIGNORE PYTHONPATH PYTHONHOME LD_PRELOAD LD_LIBRARY_PATH
PATH=/usr/bin:/bin
LC_ALL=C.UTF-8
readonly PATH LC_ALL

usage() {
  cat >&2 <<'EOF'
Usage:
  drain-legacy-v3-runtime.sh verify-only /home/bote/m/.local/ambit-daytona-c16b/state
  drain-legacy-v3-runtime.sh drain /home/bote/m/.local/ambit-daytona-c16b/state VERIFICATION_SHA256
  drain-legacy-v3-runtime.sh resume /home/bote/m/.local/ambit-daytona-c16b/state
EOF
  exit 64
}

[[ $# -ge 2 && $# -le 3 ]] || usage
operation=$1
state_root=$2
expected_state_root=/home/bote/m/.local/ambit-daytona-c16b/state
[[ ${state_root} == "${expected_state_root}" ]] || {
  echo 'legacy-v3 drain accepts only the exact audited STATE_ROOT' >&2
  exit 64
}
[[ $(/usr/bin/realpath -e -- "${state_root}") == "${state_root}" ]] || {
  echo 'legacy-v3 STATE_ROOT is not an existing canonical path' >&2
  exit 64
}

caller_uid=$(/usr/bin/id -u)
caller_gid=$(/usr/bin/id -g)
[[ ${caller_uid} == 1000 && ${caller_gid} == 1000 ]] || {
  echo 'legacy-v3 drain caller identity differs from the audited runtime' >&2
  exit 77
}

script_source=$(/usr/bin/realpath -e -- "${BASH_SOURCE[0]}")
script_dir=${script_source%/*}
tool=${script_dir}/legacy_v3_drain.py
tool_sha256=7279c1366195bda944c854192b8bb3c3f40478fbf419106cf017577323f58f33
control_root=/run/ambit-c16b-legacy-v3-drain-1577287b8182

read -r -d '' pinned_loader <<'PY' || true
import collections
import functools
import hashlib
import hmac
import itertools
import json
import os
import operator
import stat
import sys

mode, authority_path, expected_sha256, operation, state_root, caller_uid, caller_gid, *tail = sys.argv[1:]
if mode not in {"repo", "resume"}:
    raise SystemExit("legacy-v3 loader mode differs")
if os.geteuid() != 0 or os.getegid() != 0:
    raise SystemExit("legacy-v3 loader is not privileged")
if os.environ.get("SUDO_UID") != caller_uid or os.environ.get("SUDO_GID") != caller_gid:
    raise SystemExit("legacy-v3 authenticated sudo caller differs")
if state_root != "/home/bote/m/.local/ambit-daytona-c16b/state":
    raise SystemExit("legacy-v3 loader state binding differs")

def duplicate_rejector(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise SystemExit("legacy-v3 capsule contains a duplicate JSON field")
        value[key] = item
    return value

def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()

TERMINAL_TIMESTAMP_SENTINEL = "2000-01-01T00:00:00.000000+00:00"
ACQUISITION_EMPTY = object()

def terminal_projection_value_for(control, *, observed_at, boot_id):
    return {
        "schema": "ambit.local-daytona-legacy-v3-drain-terminal/v1",
        "outcome": "drained",
        "observedAt": observed_at,
        "bootId": boot_id,
        "stateRoot": "/home/bote/m/.local/ambit-daytona-c16b/state",
        "legacyReceiptSha256": "c7b6f7f5f77ae5569a918cd33a811aa855b781f3c007df6f9f19bf1d3f458c21",
        "legacyReceiptArchive": "/home/bote/m/.local/ambit-daytona-c16b/state/evidence/outer-docker-receipt.legacy-v3-c7b6f7f5f77ae556.json",
        "controlSha256": hashlib.sha256(canonical(control)).hexdigest(),
        "sourceSha256": control["sourceSha256"],
        "control": control,
        "persistentDataPreserved": [
            "/home/bote/m/.local/ambit-daytona-c16b/state/outer-docker",
            "/home/bote/m/.local/ambit-daytona-c16b/state/outer-containerd",
            "/home/bote/m/.local/ambit-daytona-c16b/state/registry",
        ],
        "legacyRuntimeRemoved": True,
        "cgroupMutationPerformed": False,
        "forceKillPerformed": False,
    }

def add_error_note(active_error, prefix, detail=None):
    try:
        if detail is None:
            note = prefix
        else:
            try:
                rendered = str(detail)
            except BaseException:
                rendered = "<unprintable " + type(detail).__name__ + ">"
            note = prefix + rendered
        BaseException.add_note(active_error, note)
    except BaseException:
        pass

class DescriptorRegistration:
    def __init__(self, descriptor):
        self.descriptor = descriptor
        self.published = False
        self.close_started = False
        self.close_finished = False
        self.close_error = None

class PendingDescriptorAcquisition:
    def __init__(self):
        self.captured = [ACQUISITION_EMPTY]
        self.registration = None

class DescriptorCustody:
    def __init__(self, label):
        self.label = label
        self.descriptors = []
        self.state = "open"
        self.cleanup_error = None
        self.pending_acquisition = None

    def _acknowledge_published_pending(self):
        pending = self.pending_acquisition
        if pending is None:
            return
        if self._acquisition_is_active(pending):
            raise SystemExit(self.label + " acquisition is still active")
        registration = pending.registration
        if not (
            registration is not None
            and registration.published
            and any(owned is registration for owned in self.descriptors)
        ):
            raise SystemExit(self.label + " prior acquisition handoff is incomplete")
        self.pending_acquisition = None

    def _admit_pending_registration(self):
        pending = self.pending_acquisition
        if pending is None:
            return
        if pending.captured[0] is ACQUISITION_EMPTY:
            self.pending_acquisition = None
            return
        descriptor = pending.captured[0]
        registration = pending.registration
        if registration is None:
            try:
                registration = DescriptorRegistration(descriptor)
            except BaseException:
                registration = object.__new__(DescriptorRegistration)
                registration.descriptor = descriptor
                registration.published = False
                registration.close_started = False
                registration.close_finished = False
                registration.close_error = None
            pending.registration = registration
        if not any(owned is registration for owned in self.descriptors):
            candidate = list.copy(self.descriptors)
            candidate.append(registration)
            self.descriptors = candidate
        registration.published = True
        self.pending_acquisition = None

    def _acquisition_is_active(self, pending):
        frame = sys._getframe(1)
        try:
            while frame is not None:
                if (
                    frame.f_code is DescriptorCustody.open.__code__
                    and frame.f_locals.get("self") is self
                    and frame.f_locals.get("pending") is pending
                ):
                    return True
                frame = frame.f_back
            return False
        finally:
            del frame

    @staticmethod
    def _capture_producer_result(captured, producer):
        collections.deque(
            map(
                functools.partial(captured.__setitem__, 0),
                itertools.starmap(producer, ((),)),
            ),
            maxlen=0,
        )

    @staticmethod
    def _invoke_closer(registration, closer):
        collections.deque(
            map(
                operator.call,
                (
                    functools.partial(
                        setattr,
                        registration,
                        "close_started",
                        True,
                    ),
                    closer,
                ),
            ),
            maxlen=0,
        )

    def open(self, *args, **kwargs):
        self._acknowledge_published_pending()
        baseline = list.copy(self.descriptors)
        pending = PendingDescriptorAcquisition()
        self.pending_acquisition = pending
        registration = None
        try:
            producer = functools.partial(os.open, *args, **kwargs)
            self._capture_producer_result(pending.captured, producer)
            if pending.captured[0] is ACQUISITION_EMPTY:
                raise SystemExit(self.label + " producer returned no descriptor")
            descriptor = pending.captured[0]
            registration = DescriptorRegistration(descriptor)
            pending.registration = registration
            if type(descriptor) is not int or descriptor < 0:
                raise SystemExit(self.label + " acquired descriptor is invalid")
            if self.state != "open" or self.cleanup_error is not None:
                raise SystemExit(
                    self.label + " registration is unavailable while "
                    + self.state + " or cleanup is ambiguous"
                )
            candidate = list.copy(baseline)
            candidate.append(registration)
            self.descriptors = candidate
            registration.published = True
            return descriptor
        except BaseException as error:
            if pending.captured[0] is ACQUISITION_EMPTY:
                if self.pending_acquisition is pending:
                    self.pending_acquisition = None
                raise
            descriptor = pending.captured[0]
            if registration is None:
                try:
                    registration = DescriptorRegistration(descriptor)
                except BaseException as registration_error:
                    add_error_note(
                        error,
                        self.label + " registration construction also failed: ",
                        registration_error,
                    )
                    registration = object.__new__(DescriptorRegistration)
                    registration.descriptor = descriptor
                    registration.published = False
                    registration.close_started = False
                    registration.close_finished = False
                    registration.close_error = None
            pending.registration = registration
            for _attempt in range(2):
                try:
                    self._restore_roster(baseline, registration, error)
                    break
                except BaseException as escaped_restore:
                    add_error_note(
                        error,
                        self.label + " roster restoration escaped: ",
                        escaped_restore,
                    )
            cleanup_error = None
            for _attempt in range(2):
                try:
                    cleanup_error = self._settle_once(registration)
                    break
                except BaseException as escaped_cleanup:
                    cleanup_error = escaped_cleanup
                    add_error_note(
                        error,
                        self.label + " registration cleanup escaped: ",
                        escaped_cleanup,
                    )
                    if registration.close_started:
                        break
            if cleanup_error is not None:
                add_error_note(
                    error,
                    self.label + " registration cleanup also failed: ",
                    cleanup_error,
                )
            if (
                self.pending_acquisition is pending
                and (registration.close_started or registration.close_finished)
            ):
                self.pending_acquisition = None
            raise

    def _restore_roster(self, baseline, registration, active_error):
        first_error = None
        for _attempt in range(2):
            try:
                # Restore roster and publication state at one trace boundary.
                self.descriptors = list.copy(baseline); registration.published = False
                if first_error is not None:
                    add_error_note(
                        active_error,
                        self.label + " roster restoration first failed: ",
                        first_error,
                    )
                return
            except BaseException as restore_error:
                if first_error is None:
                    first_error = restore_error
                else:
                    add_error_note(
                        active_error,
                        self.label + " roster restoration also failed: ",
                        restore_error,
                    )
        if first_error is not None:
            add_error_note(
                active_error,
                self.label + " roster restoration remained incomplete: ",
                first_error,
            )

    def _close_once(self, registration):
        if registration.close_error is not None or registration.close_finished:
            return registration.close_error
        if registration.close_started:
            return None
        preinvoke_error = None
        while not registration.close_started:
            try:
                closer = functools.partial(os.close, registration.descriptor)
                self._invoke_closer(registration, closer)
                registration.close_finished = True
            except BaseException as cleanup_error:
                if not registration.close_started:
                    if preinvoke_error is None:
                        preinvoke_error = cleanup_error
                    else:
                        add_error_note(
                            preinvoke_error,
                            self.label + " repeated pre-close interruption: ",
                            cleanup_error,
                        )
                    continue
                registration.close_error = cleanup_error; registration.close_finished = True
                if preinvoke_error is not None:
                    add_error_note(
                        preinvoke_error,
                        self.label + " cleanup also failed: ",
                        cleanup_error,
                    )
                    registration.close_error = preinvoke_error
                    return preinvoke_error
                return registration.close_error
        if preinvoke_error is not None:
            registration.close_error = preinvoke_error
        return registration.close_error

    def _settle_once(self, registration):
        first_error = None
        for _attempt in range(2):
            try:
                observed_error = self._close_once(registration)
            except BaseException as escaped_error:
                observed_error = escaped_error
            if (
                registration.close_started
                and registration.close_error is None
                and observed_error is not None
                and isinstance(observed_error.__context__, BaseException)
            ):
                registration.close_error = observed_error.__context__
                registration.close_finished = True
                add_error_note(
                    registration.close_error,
                    self.label + " cleanup persistence also failed: ",
                    observed_error,
                )
            if registration.close_started and registration.close_error is not None:
                if observed_error is not None and observed_error is not registration.close_error:
                    add_error_note(
                        registration.close_error,
                        self.label + " cleanup settlement also failed: ",
                        observed_error,
                    )
                observed_error = registration.close_error
            if first_error is None and observed_error is not None:
                first_error = observed_error
            elif observed_error is not None and observed_error is not first_error:
                add_error_note(
                    first_error,
                    self.label + " cleanup retry also failed: ",
                    observed_error,
                )
            if registration.close_started or registration.close_finished:
                return first_error
        return first_error

    def _cleanup_is_active(self, registration):
        frame = sys._getframe(1)
        try:
            while frame is not None:
                if (
                    frame.f_code is DescriptorCustody._close_once.__code__
                    and frame.f_locals.get("self") is self
                    and frame.f_locals.get("registration") is registration
                ):
                    return True
                frame = frame.f_back
            return False
        finally:
            del frame

    def _publish_terminal_error(self, registration, error):
        if registration.close_error is None:
            # A synthetic rejection never claims that os.close was invoked.
            registration.close_error, registration.close_finished = error, True
            return error
        registration.close_finished = True
        if registration.close_error is not error:
            add_error_note(
                registration.close_error,
                self.label + " additional terminal error: ",
                error,
            )
        return registration.close_error

    def _record_cleanup_error(self, error):
        if self.cleanup_error is None:
            self.cleanup_error = error
            return
        if self.cleanup_error is not error:
            add_error_note(
                self.cleanup_error,
                self.label + " additional cleanup also failed: ",
                error,
            )

    def close(self):
        pending = self.pending_acquisition
        if pending is not None and self._acquisition_is_active(pending):
            raise SystemExit(self.label + " acquisition is still active")
        self._admit_pending_registration()
        if self.state == "closed" and not self.descriptors:
            if self.cleanup_error is not None:
                raise self.cleanup_error
            return
        completed = False
        try:
            self.state = "closing"
            roster = list.copy(self.descriptors)
            registrations = []
            seen_tokens = set()
            for registration in reversed(roster):
                token = id(registration)
                if token in seen_tokens:
                    continue
                seen_tokens.add(token)
                registrations.append(registration)

            invalid = []
            groups = {}
            for registration in registrations:
                descriptor = registration.descriptor
                if type(descriptor) is not int or descriptor < 0:
                    invalid.append(registration)
                    continue
                groups.setdefault(descriptor, []).append(registration)

            for registration in invalid:
                invalid_error = self._publish_terminal_error(
                    registration,
                    SystemExit(self.label + " cleanup descriptor is invalid"),
                )
                self._record_cleanup_error(invalid_error)

            unique = []
            for group in groups.values():
                authority = next(
                    (
                        registration
                        for registration in group
                        if registration.close_started
                        and self._cleanup_is_active(registration)
                    ),
                    next(
                        (
                            registration
                            for registration in group
                            if registration.close_started
                        ),
                        group[0],
                    ),
                )
                if len(group) > 1:
                    alias_error = SystemExit(
                        self.label + " cleanup roster aliases one descriptor"
                    )
                    for registration in group:
                        if registration is authority:
                            continue
                        observed_error = self._publish_terminal_error(
                            registration,
                            alias_error,
                        )
                        self._record_cleanup_error(observed_error)

                if authority.close_error is not None:
                    observed_error = self._publish_terminal_error(
                        authority,
                        authority.close_error,
                    )
                    self._record_cleanup_error(observed_error)
                    continue
                if authority.close_started:
                    if self._cleanup_is_active(authority):
                        continue
                    if not authority.close_finished:
                        observed_error = self._publish_terminal_error(
                            authority,
                            SystemExit(
                                self.label + " cleanup invocation is ambiguous"
                            ),
                        )
                        self._record_cleanup_error(observed_error)
                    continue
                if authority.close_finished:
                    observed_error = self._publish_terminal_error(
                        authority,
                        SystemExit(
                            self.label + " cleanup completion is ambiguous"
                        ),
                    )
                    self._record_cleanup_error(observed_error)
                    continue
                unique.append(authority)
            for registration in unique:
                cleanup_error = self._settle_once(registration)
                if cleanup_error is not None:
                    self._record_cleanup_error(cleanup_error)
            completed = True
        finally:
            if completed:
                # An interrupted line leaves CLOSING resumable with the old roster.
                self.descriptors = []; self.state = "closed"
            else:
                self.state = "closing"
        if self.cleanup_error is not None:
            raise self.cleanup_error

    def __enter__(self):
        if self.state != "open" or self.cleanup_error is not None:
            raise SystemExit(self.label + " custody is not safely open")
        return self

    def __exit__(self, _exception_type, active_error, _traceback):
        cleanup_error = None
        for _attempt in range(2):
            try:
                self.close()
                break
            except BaseException as observed_error:
                if cleanup_error is None:
                    cleanup_error = observed_error
                else:
                    add_error_note(
                        cleanup_error,
                        self.label + " cleanup retry also failed: ",
                        observed_error,
                    )
        if self.cleanup_error is not None:
            persisted = SystemExit(self.label + " cleanup failed")
            persisted.__cause__ = self.cleanup_error
            if cleanup_error is not None:
                add_error_note(
                    persisted,
                    self.label + " settlement also failed: ",
                    cleanup_error,
                )
            cleanup_error = persisted
        if cleanup_error is not None:
            if active_error is None:
                raise cleanup_error
            add_error_note(
                active_error,
                self.label + " cleanup also failed: ",
                cleanup_error,
            )

def read_bound_at(directory_fd, name, maximum, *, expected_device=None):
    with DescriptorCustody("legacy-v3 bound read " + name) as custody:
        descriptor = custody.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
        before = os.fstat(descriptor)
        if not (
            stat.S_ISREG(before.st_mode)
            and before.st_uid == 0
            and before.st_gid == 0
            and stat.S_IMODE(before.st_mode) == 0o400
            and before.st_nlink == 1
            and 0 < before.st_size <= maximum
            and (expected_device is None or before.st_dev == expected_device)
        ):
            raise SystemExit("legacy-v3 capsule file identity differs: " + name)
        source = bytearray()
        while len(source) <= maximum:
            block = os.read(descriptor, min(64 * 1024, maximum + 1 - len(source)))
            if not block:
                break
            source.extend(block)
        after = os.fstat(descriptor)
        literal = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if not (
            len(source) == before.st_size
            and (after.st_dev, after.st_ino, after.st_size, after.st_uid, after.st_gid,
                 stat.S_IMODE(after.st_mode), after.st_nlink)
            == (before.st_dev, before.st_ino, before.st_size, before.st_uid, before.st_gid,
                stat.S_IMODE(before.st_mode), before.st_nlink)
            and (literal.st_dev, literal.st_ino) == (before.st_dev, before.st_ino)
        ):
            raise SystemExit("legacy-v3 capsule file changed during read: " + name)
        return bytes(source)

def execute_source(source, display_name, control_root_fd=None, control_root_owner=None):
    if not hmac.compare_digest(hashlib.sha256(source).hexdigest(), expected_sha256):
        raise SystemExit("legacy-v3 pinned Python source digest differs")
    os.chdir("/")
    os.environ.clear()
    os.environ.update({
        "HOME": "/root", "LC_ALL": "C.UTF-8", "PATH": "/usr/bin:/bin",
        "SUDO_UID": caller_uid, "SUDO_GID": caller_gid,
    })
    sys.argv = [display_name, operation, state_root, caller_uid, caller_gid, *tail]
    namespace = {
        "__name__": "__main__",
        "__file__": display_name,
        "__package__": None,
        "__legacy_pinned_source_bytes__": source,
    }
    if control_root_fd is not None:
        if control_root_owner is None:
            raise SystemExit("legacy-v3 control-root owner is absent")
        namespace["__legacy_control_root_fd__"] = control_root_fd
        namespace["__legacy_control_root_owner__"] = control_root_owner
    exec(compile(source, display_name, "exec"), namespace, namespace)

if mode == "repo":
    with DescriptorCustody("legacy-v3 repository source") as custody:
        descriptor = custody.open(authority_path, os.O_RDONLY | os.O_NOFOLLOW)
        before = os.fstat(descriptor)
        if not (
            stat.S_ISREG(before.st_mode)
            and before.st_uid == int(caller_uid)
            and before.st_gid == int(caller_gid)
            and stat.S_IMODE(before.st_mode) == 0o644
            and before.st_nlink == 1
            and 0 < before.st_size <= 4 * 1024 * 1024
        ):
            raise SystemExit("legacy-v3 repository source identity differs")
        source = bytearray()
        while len(source) <= 4 * 1024 * 1024:
            block = os.read(descriptor, min(64 * 1024, 4 * 1024 * 1024 + 1 - len(source)))
            if not block:
                break
            source.extend(block)
        after = os.fstat(descriptor)
        literal = os.stat(authority_path, follow_symlinks=False)
        if not (
            len(source) == before.st_size
            and (after.st_dev, after.st_ino, after.st_size, after.st_uid, after.st_gid,
                 stat.S_IMODE(after.st_mode), after.st_nlink)
            == (before.st_dev, before.st_ino, before.st_size, before.st_uid, before.st_gid,
                stat.S_IMODE(before.st_mode), before.st_nlink)
            and (literal.st_dev, literal.st_ino) == (before.st_dev, before.st_ino)
        ):
            raise SystemExit("legacy-v3 repository source changed during admission")
        source = bytes(source)
    display_name = authority_path
def execute_resume_owned(custody):
    if authority_path != "/run/ambit-c16b-legacy-v3-drain-1577287b8182":
        raise SystemExit("legacy-v3 control-root path differs")
    with DescriptorCustody("legacy-v3 resume control parent") as run_custody:
        run_fd = run_custody.open("/run", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        run_identity = os.fstat(run_fd)
        if not (
            stat.S_ISDIR(run_identity.st_mode)
            and run_identity.st_uid == 0
            and run_identity.st_gid == 0
            and stat.S_IMODE(run_identity.st_mode) & 0o022 == 0
        ):
            raise SystemExit("legacy-v3 control parent differs")
        control_root_fd = custody.open(
            "ambit-c16b-legacy-v3-drain-1577287b8182",
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=run_fd,
        )
        root = os.fstat(control_root_fd)
        literal = os.stat(
            "ambit-c16b-legacy-v3-drain-1577287b8182",
            dir_fd=run_fd,
            follow_symlinks=False,
        )
        if not (
            stat.S_ISDIR(root.st_mode)
            and root.st_uid == 0
            and root.st_gid == 0
            and stat.S_IMODE(root.st_mode) == 0o700
            and (literal.st_dev, literal.st_ino) == (root.st_dev, root.st_ino)
        ):
            raise SystemExit("legacy-v3 root control identity differs")
    allowed = {
        "legacy_v3_drain.py", "control.json", "state.json",
        ".legacy_v3_drain.py.pending", ".control.json.pending", ".state.json.pending",
    }
    entries = set(os.listdir(control_root_fd))
    if not {"legacy_v3_drain.py", "control.json", "state.json"} <= entries <= allowed:
        raise SystemExit("legacy-v3 root control roster differs")
    source = read_bound_at(control_root_fd, "legacy_v3_drain.py", 4 * 1024 * 1024, expected_device=root.st_dev)
    raw_control = read_bound_at(control_root_fd, "control.json", 2 * 1024 * 1024, expected_device=root.st_dev)
    raw_state = read_bound_at(control_root_fd, "state.json", 2 * 1024 * 1024, expected_device=root.st_dev)
    control = json.loads(raw_control, object_pairs_hook=duplicate_rejector)
    state = json.loads(raw_state, object_pairs_hook=duplicate_rejector)
    if not isinstance(control, dict) or set(control) != {
        "schema", "observedAt", "bootId", "stateRoot", "caller",
        "verificationSha256", "sourceSha256", "authority",
    }:
        raise SystemExit("legacy-v3 root control shape differs")
    if not isinstance(state, dict) or set(state) != {
        "schema", "observedAt", "bootId", "stateRoot", "controlSha256", "phase",
        "netnsMarkerIdentity",
    }:
        raise SystemExit("legacy-v3 root state shape differs")
    boot_path = "/proc/sys/kernel/random/boot_id"
    with DescriptorCustody("legacy-v3 resume boot identity") as boot_custody:
        boot_fd = boot_custody.open(boot_path, os.O_RDONLY | os.O_NOFOLLOW)
        boot_before = os.fstat(boot_fd)
        boot_raw = os.read(boot_fd, 129)
        boot_tail = os.read(boot_fd, 1)
        boot_after = os.fstat(boot_fd)
        boot_literal = os.stat(boot_path, follow_symlinks=False)
        if not (
            stat.S_ISREG(boot_before.st_mode)
            and boot_before.st_uid == 0
            and boot_before.st_gid == 0
            and not boot_tail
            and 0 < len(boot_raw) <= 128
            and (boot_after.st_dev, boot_after.st_ino, stat.S_IFMT(boot_after.st_mode))
            == (boot_before.st_dev, boot_before.st_ino, stat.S_IFMT(boot_before.st_mode))
            == (boot_literal.st_dev, boot_literal.st_ino, stat.S_IFMT(boot_literal.st_mode))
        ):
            raise SystemExit("legacy-v3 boot identity file differs")
    boot_id = boot_raw.decode("ascii", "strict").strip()
    phases = {
        "stopping_intent_final", "runtime_custody_transferred", "docker_api_revoked",
        "dockerd_stop_requested", "dockerd_stopped", "container_graph_quiesced",
        "containerd_stop_requested", "containerd_stopped", "mounts_settled",
        "runtime_reducing", "runtime_empty", "archive_intent_final",
    }
    if not (
        control["schema"] == "ambit.local-daytona-legacy-v3-drain-control/v1"
        and state["schema"] == "ambit.local-daytona-legacy-v3-drain-state/v1"
        and control["bootId"] == state["bootId"] == boot_id
        and control["stateRoot"] == state["stateRoot"] == state_root
        and control["caller"] == {"uid": 1000, "gid": 1000}
        and isinstance(control["authority"], dict)
        and hmac.compare_digest(control["verificationSha256"], hashlib.sha256(canonical(control["authority"])).hexdigest())
        and hmac.compare_digest(state["controlSha256"], hashlib.sha256(canonical(control)).hexdigest())
        and state["phase"] in phases
        and (
            (state["phase"] in {"mounts_settled", "runtime_reducing", "runtime_empty", "archive_intent_final"}
             and isinstance(state["netnsMarkerIdentity"], dict))
            or
            (state["phase"] not in {"mounts_settled", "runtime_reducing", "runtime_empty", "archive_intent_final"}
             and state["netnsMarkerIdentity"] is None)
        )
    ):
        raise SystemExit("legacy-v3 root control binding differs")
    if not hmac.compare_digest(hashlib.sha256(source).hexdigest(), control["sourceSha256"]):
        raise SystemExit("legacy-v3 root source snapshot differs")
    terminal_observed_at = (
        state["observedAt"]
        if state["phase"] == "archive_intent_final"
        else TERMINAL_TIMESTAMP_SENTINEL
    )
    terminal_projection = terminal_projection_value_for(
        control,
        observed_at=terminal_observed_at,
        boot_id=state["bootId"],
    )
    if not (0 < len(canonical(terminal_projection)) <= 2 * 1024 * 1024):
        raise SystemExit("legacy-v3 terminal projection is too large")
    display_name = authority_path + "/legacy_v3_drain.py"
    execute_source(source, display_name, control_root_fd, custody)

if mode == "repo":
    execute_source(source, display_name)
else:
    with DescriptorCustody("legacy-v3 resume authority") as resume_custody:
        execute_resume_owned(resume_custody)
PY

invoke_tool() {
  local mode=$1
  shift
  /usr/bin/sudo -n -- /usr/bin/python3 -I -S -B -c "${pinned_loader}" \
    "${mode}" "$@"
}

case ${operation} in
  verify-only)
    [[ $# -eq 2 ]] || usage
    invoke_tool repo "${tool}" "${tool_sha256}" verify-only \
      "${state_root}" "${caller_uid}" "${caller_gid}"
    ;;
  drain)
    [[ $# -eq 3 && $3 =~ ^[0-9a-f]{64}$ ]] || usage
    invoke_tool repo "${tool}" "${tool_sha256}" drain \
      "${state_root}" "${caller_uid}" "${caller_gid}" "$3"
    ;;
  resume)
    [[ $# -eq 2 ]] || usage
    if [[ -e ${control_root} || -L ${control_root} ]]; then
      invoke_tool resume "${control_root}" "${tool_sha256}" resume \
        "${state_root}" "${caller_uid}" "${caller_gid}"
    else
      invoke_tool repo "${tool}" "${tool_sha256}" resume \
        "${state_root}" "${caller_uid}" "${caller_gid}"
    fi
    ;;
  *)
    usage
    ;;
esac
