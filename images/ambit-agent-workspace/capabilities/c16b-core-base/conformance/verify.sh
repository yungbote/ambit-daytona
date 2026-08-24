#!/bin/sh
set -u

fail() {
  code=$1
  shift
  printf 'core-conformance:%s\n' "$*" >&2
  exit "$code"
}

equal() {
  actual=$1
  expected=$2
  code=$3
  message=$4
  test "$actual" = "$expected" || fail "$code" "$message"
}

mount_has_option() {
  mountpoint=$1
  option=$2
  awk -v mountpoint="$mountpoint" -v option="$option" '
    $5 == mountpoint {
      count += 1
      split($6, values, ",")
      for (item in values) if (values[item] == option) found = 1
    }
    END { exit !(count == 1 && found == 1) }
  ' /proc/self/mountinfo
}

helper=/opt/ambit/runtime-pack/core-document/bin/ambit-atomic-materialize

equal "$(id -u)" 1000 10 'uid-is-not-1000'
equal "$(id -g)" 1000 11 'gid-is-not-1000'
equal "$(id -un)" daytona 12 'user-is-not-daytona'
equal "$(id -G)" 1000 13 'supplementary-group-roster-is-not-exact'

environment_names=$(env | cut -d= -f1 | LC_ALL=C sort)
expected_environment_names=$(printf '%s\n' \
  HOME HOSTNAME LANG LC_ALL PATH PWD TZ | LC_ALL=C sort)
equal "$environment_names" "$expected_environment_names" 14 \
  'environment-name-roster-is-not-exact'
equal "$HOME" /workspace 15 'home-is-not-workspace'
equal "$LANG" C.UTF-8 16 'lang-is-not-c-utf8'
equal "$LC_ALL" C.UTF-8 17 'lc-all-is-not-c-utf8'
equal "$PATH" /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin 18 \
  'path-roster-is-not-exact'
equal "$PWD" /workspace 19 'working-directory-is-not-workspace'
equal "$TZ" UTC 20 'timezone-is-not-utc'

capability_rows=$(awk '
  $1 ~ /^Cap(Inh|Prm|Eff|Bnd|Amb):$/ { print $1 $2 }
' /proc/self/status | LC_ALL=C sort)
expected_capability_rows=$(printf '%s\n' \
  'CapAmb:0000000000000000' \
  'CapBnd:0000000000000000' \
  'CapEff:0000000000000000' \
  'CapInh:0000000000000000' \
  'CapPrm:0000000000000000' | LC_ALL=C sort)
equal "$capability_rows" "$expected_capability_rows" 23 \
  'linux-capability-vector-is-not-all-zero'
no_new_privileges=$(awk '$1 == "NoNewPrivs:" { print $2 }' /proc/self/status)
equal "$no_new_privileges" 1 24 'no-new-privileges-is-not-set'

interfaces=$(find /sys/class/net -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C sort)
equal "$interfaces" lo 25 'network-namespace-is-not-loopback-only'
printf '%s\n' "$HOSTNAME" | grep -Eq '^[0-9a-f]{12}$' || \
  fail 21 'hostname-is-not-a-docker-container-id'
equal "$(hostname)" "$HOSTNAME" 22 'hostname-command-and-environment-differ'

mountpoints=$(awk '
  { for (field = 1; field <= NF; field += 1) if ($field == "-") { print $5; break } }
' /proc/self/mountinfo | LC_ALL=C sort)
expected_mountpoints=$(printf '%s\n' \
  / \
  /dev \
  /dev/mqueue \
  /dev/pts \
  /dev/shm \
  /etc/hostname \
  /etc/hosts \
  /etc/resolv.conf \
  /proc \
  /proc/acpi \
  /proc/asound \
  /proc/bus \
  /proc/fs \
  /proc/interrupts \
  /proc/irq \
  /proc/kcore \
  /proc/keys \
  /proc/scsi \
  /proc/sys \
  /proc/sysrq-trigger \
  /proc/timer_list \
  /sys \
  /sys/devices/virtual/powercap \
  /sys/firmware \
  /sys/fs/cgroup \
  /workspace | LC_ALL=C sort)
equal "$mountpoints" "$expected_mountpoints" 26 'mountpoint-roster-is-not-exact'

root_filesystem=$(awk '
  $5 == "/" { for (field = 1; field <= NF; field += 1) if ($field == "-") print $(field + 1) }
' /proc/self/mountinfo)
equal "$root_filesystem" overlay 27 'root-filesystem-is-not-overlay'
mount_has_option / ro || fail 28 'root-filesystem-is-not-read-only'
mount_has_option /workspace rw || fail 29 'workspace-is-not-writable'
mount_has_option /workspace nosuid || fail 30 'workspace-allows-suid'
mount_has_option /workspace nodev || fail 31 'workspace-allows-devices'
mount_has_option /workspace noexec || fail 32 'workspace-allows-execution'
mount_has_option /sys ro || fail 33 'sysfs-is-not-read-only'
mount_has_option /sys/fs/cgroup ro || fail 34 'cgroup-is-not-read-only'
for mountpoint in /etc/hostname /etc/hosts /etc/resolv.conf; do
  mount_has_option "$mountpoint" ro || fail 35 'docker-host-file-is-not-read-only'
done

sockets=$(find / -type s -print 2>/dev/null | LC_ALL=C sort || true)
equal "$sockets" '' 36 'unix-socket-census-is-not-empty'
workspace_entries=$(find /workspace -mindepth 1 -print -quit)
equal "$workspace_entries" '' 37 'workspace-is-not-empty'

test -x /bin/sh || fail 38 'posix-shell-is-absent'
test -x /bin/bash || fail 39 'bash-is-absent'
test -x "$helper" || fail 40 'materializer-is-not-executable'
equal "$(sha256sum "$helper" | cut -d ' ' -f 1)" \
  8d4405a1bd8f5d9d65be0860e52cab75cc9b7f5f659e510b4932347e0c6008e5 \
  41 'materializer-digest-differs'
equal "$(stat -c '%a:%u:%g:%h' "$helper")" 555:0:0:1 42 \
  'materializer-identity-differs'
equal "$(sha256sum /usr/share/licenses/ambit-atomic-materialize/ATOMIC-MATERIALIZER-LICENSE.md | cut -d ' ' -f 1)" \
  ebda4883114f2939d766c552df33881f40da5710f6af5abbfe31a92c73070aff \
  43 'materializer-license-digest-differs'
equal "$(sha256sum /usr/share/licenses/ambit-atomic-materialize/atomic-materializer-license.lock.json | cut -d ' ' -f 1)" \
  710d581169c105538897e9b6a719c47d437ceaeb980784e7996f8227264cc89c \
  44 'materializer-license-lock-digest-differs'

for command in apt apt-get apt-cache apt-config dpkg dpkg-query dpkg-deb \
  pip pip3 python python3 node npm npx libreoffice soffice chromium playwright; do
  command -v "$command" >/dev/null 2>&1 && \
    fail 45 'runtime-installer-or-specialist-command-is-present'
done
for path in /etc/apt /etc/dpkg /usr/lib/apt /usr/lib/dpkg /var/lib/apt \
  /var/lib/dpkg /var/cache/apt /var/cache/debconf /usr/share/python-wheels; do
  test ! -e "$path" || fail 46 'runtime-installer-state-is-present'
done
installer_executables=$(find / -xdev \( -type f -o -type l \) -perm /111 \
  \( -name 'apt*' -o -name 'dpkg*' -o -name 'pip*' -o -name 'npm*' -o -name 'npx*' \) \
  -print 2>/dev/null | LC_ALL=C sort || true)
equal "$installer_executables" '' 47 'runtime-installer-executable-payload-is-present'
installer_named_paths=$(find / -xdev \( -iname '*apt*' -o -iname '*dpkg*' \) \
  -print 2>/dev/null | LC_ALL=C sort | \
  grep -Fvx '/opt/ambit/runtime-base/core/lineage/base-installed-dpkg.lock' | \
  grep -Fvx '/usr/bin/captoinfo' || true)
equal "$installer_named_paths" '' 48 'runtime-installer-named-payload-is-present'

printf '%s\n' \
  '{"capabilities":["ambit.runtime/command.execute@1","ambit.runtime/filesystem.read-write@1"],"environmentNames":["HOME","HOSTNAME","LANG","LC_ALL","PATH","PWD","TZ"],"helperSha256":"sha256:8d4405a1bd8f5d9d65be0860e52cab75cc9b7f5f659e510b4932347e0c6008e5","hostSockets":"absent-global-census","linuxCapabilitySets":{"ambient":"none","bounding":"none","effective":"none","inheritable":"none","permitted":"none"},"mountTopology":"exact","network":"none-loopback-only","noNewPrivileges":true,"outcome":"passed","privilege":"uid-gid-groups-1000-only","rootFilesystem":"kernel-mount-read-only","runtimeInstallerExecutablePayload":"absent","schema":"ambit.runtime-core-base-conformance/v2","workspace":"empty-private-tmpfs"}'
