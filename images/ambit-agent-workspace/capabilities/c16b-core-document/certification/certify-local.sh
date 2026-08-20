#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: certify-local.sh SOURCE_REVISION ARTIFACT_ROOT

Required environment:
  BACKEND_REPO                 absolute backend Git worktree/repository
  GRYPE_DB_CACHE_DIR           absolute immutable Grype database cache
  GRYPE_DB_EXPECTED_TREE_SHA256 expected lowercase SHA-256 of cache file manifest
  VEX_EVIDENCE_DIR             absolute directory containing the exact reviewed snapshots
  GLIBC_GIT_DIR                absolute Git repository containing every locked glibc fix/source commit
  OPENSSL_GIT_DIR              absolute Git repository containing the locked OpenSSL source/fix commits
  PROVIDER_ADAPTER_RECEIPT     absolute passed backend adapter test receipt
  PROVIDER_ADAPTER_LOG         absolute raw log bound by the adapter receipt

The command builds and pushes a candidate to a task-local loopback registry,
retrieves OCI objects by digest, tests the exact linux/amd64 manifest under
network-none/non-root/read-only controls, scans and verifies the complete raw
SBOM/VEX/license policy, scans every saved image layer for secrets, and signs
one content binding with an ephemeral local Ed25519 key. It has no promotion
command and never writes an active tag.
EOF
}

sha256_file() {
  sha256sum "$1" | cut -d' ' -f1
}

require_absolute_directory() {
  local name=$1
  local value=$2
  [[ ${value} = /* && -d ${value} ]] || {
    echo "${name} must be an existing absolute directory" >&2
    exit 64
  }
}

require_absolute_file() {
  local name=$1
  local value=$2
  [[ ${value} = /* && -f ${value} ]] || {
    echo "${name} must be an existing absolute regular file" >&2
    exit 64
  }
}

hash_set() {
  local root=$1
  local output=$2
  shift 2
  (
    cd "${root}"
    local item
    for item in "$@"; do
      [[ -f ${item} ]] || { echo "missing source input: ${item}" >&2; exit 1; }
      sha256sum "${item}"
    done
  ) > "${output}"
}

if [[ ${1:-} == "--help" && $# -eq 1 ]]; then
  usage
  exit 0
fi
if [[ $# -ne 2 ]]; then
  usage >&2
  exit 64
fi

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
pack_dir=$(cd "${script_dir}/.." && pwd)
repo_root=$(git -C "${pack_dir}" rev-parse --show-toplevel)
pack_path=${pack_dir#"${repo_root}/"}
source_revision=$(git -C "${repo_root}" rev-parse --verify "${1}^{commit}")
source_head=$(git -C "${repo_root}" rev-parse HEAD)
source_tree=$(git -C "${repo_root}" rev-parse "${source_revision}^{tree}")
source_pack_tree=$(git -C "${repo_root}" rev-parse "${source_revision}:${pack_path}")
source_date_epoch=$(git -C "${repo_root}" show -s --format=%ct "${source_revision}")
artifact_root=$2

backend_repo=${BACKEND_REPO:?BACKEND_REPO is required}
grype_cache=${GRYPE_DB_CACHE_DIR:?GRYPE_DB_CACHE_DIR is required}
grype_expected_tree=${GRYPE_DB_EXPECTED_TREE_SHA256:?GRYPE_DB_EXPECTED_TREE_SHA256 is required}
vex_evidence_dir=${VEX_EVIDENCE_DIR:?VEX_EVIDENCE_DIR is required}
glibc_git_dir=${GLIBC_GIT_DIR:?GLIBC_GIT_DIR is required}
openssl_git_dir=${OPENSSL_GIT_DIR:?OPENSSL_GIT_DIR is required}
provider_adapter_receipt=${PROVIDER_ADAPTER_RECEIPT:?PROVIDER_ADAPTER_RECEIPT is required}
provider_adapter_log=${PROVIDER_ADAPTER_LOG:?PROVIDER_ADAPTER_LOG is required}

[[ ${artifact_root} = /home/* ]] || { echo "ARTIFACT_ROOT must be on /home storage" >&2; exit 64; }
[[ ! -e ${artifact_root} ]] || { echo "ARTIFACT_ROOT already exists: ${artifact_root}" >&2; exit 65; }
[[ -z $(git -C "${repo_root}" status --porcelain --untracked-files=all) ]] || {
  echo "Daytona repository must be tracked-clean" >&2
  exit 66
}
[[ ${source_revision} == "${source_head}" ]] || {
  echo "SOURCE_REVISION must equal clean Daytona HEAD" >&2
  exit 66
}
require_absolute_directory BACKEND_REPO "${backend_repo}"
require_absolute_directory GRYPE_DB_CACHE_DIR "${grype_cache}"
require_absolute_directory VEX_EVIDENCE_DIR "${vex_evidence_dir}"
require_absolute_directory GLIBC_GIT_DIR "${glibc_git_dir}"
require_absolute_directory OPENSSL_GIT_DIR "${openssl_git_dir}"
require_absolute_file PROVIDER_ADAPTER_RECEIPT "${provider_adapter_receipt}"
require_absolute_file PROVIDER_ADAPTER_LOG "${provider_adapter_log}"
[[ ${grype_expected_tree} =~ ^[0-9a-f]{64}$ ]] || { echo "invalid expected Grype DB tree digest" >&2; exit 64; }

builder_name="ambit-c16b-certify-${BASHPID}"
registry_name="ambit-c16b-registry-${BASHPID}"
private_key=
signing_dir=
socket_fixture=
socket_pid=

cleanup() {
  local status=$?
  if [[ -n ${socket_pid} ]]; then
    kill "${socket_pid}" >/dev/null 2>&1 || true
    wait "${socket_pid}" >/dev/null 2>&1 || true
  fi
  if [[ -n ${private_key} && -e ${private_key} ]]; then
    shred -u -- "${private_key}" >/dev/null 2>&1 || unlink "${private_key}" >/dev/null 2>&1 || true
  fi
  if [[ -n ${signing_dir} && -d ${signing_dir} ]]; then
    rmdir "${signing_dir}" >/dev/null 2>&1 || true
  fi
  docker buildx rm "${builder_name}" >/dev/null 2>&1 || true
  docker rm -f "${registry_name}" >/dev/null 2>&1 || true
  exit "${status}"
}
trap cleanup EXIT INT TERM

mkdir -p \
  "${artifact_root}/source-context" \
  "${artifact_root}/helper-context" \
  "${artifact_root}/registry-data" \
  "${artifact_root}/oci" \
  "${artifact_root}/security" \
  "${artifact_root}/vex-primary" \
  "${artifact_root}/transport"

jq -n -S \
  --arg bash "$(bash --version | sed -n '1p')" \
  --arg git "$(git --version)" \
  --arg docker "$(docker version --format '{{.Client.Version}}/{{.Server.Version}}')" \
  --arg buildx "$(docker buildx version)" \
  --arg jq "$(jq --version)" \
  --arg openssl "$(openssl version)" \
  --arg go "$(go version)" \
  --arg python "$(python3 --version)" \
  --arg tar "$(tar --version | sed -n '1p')" \
  --arg curl "$(curl --version | sed -n '1p')" \
  '{schema:"ambit.runtime-pack-certification-host-tools/v1",bash:$bash,git:$git,docker:$docker,buildx:$buildx,jq:$jq,openssl:$openssl,go:$go,python:$python,tar:$tar,curl:$curl}' \
  > "${artifact_root}/certification-host-tools.json"

source_archive=${artifact_root}/daytona-pack-source.tar
git -C "${repo_root}" archive --format=tar "${source_revision}" -- "${pack_path}" > "${source_archive}"
source_archive_sha256=$(sha256_file "${source_archive}")
tar -xf "${source_archive}" -C "${artifact_root}/source-context"
archived_pack_dir=${artifact_root}/source-context/${pack_path}
archived_cert_dir=${archived_pack_dir}/certification
archived_policy_dir=${archived_pack_dir}/policy

helper_lock=${archived_pack_dir}/helper-input.lock.json
helper_revision=$(jq -er '.revision' "${helper_lock}")
helper_tree=$(jq -er '.tree' "${helper_lock}")
helper_path=$(jq -er '.path' "${helper_lock}")
helper_archive_expected=$(jq -er '.archive.sha256' "${helper_lock}")
helper_archive=${artifact_root}/backend-helper-source.tar
[[ $(git -C "${backend_repo}" rev-parse "${helper_revision}:${helper_path}") == "${helper_tree}" ]] || {
  echo "backend helper tree differs from committed helper lock" >&2
  exit 66
}
git -C "${backend_repo}" archive --format=tar "${helper_revision}" -- "${helper_path}" > "${helper_archive}"
helper_archive_sha256=$(sha256_file "${helper_archive}")
[[ ${helper_archive_sha256} == "${helper_archive_expected}" ]] || {
  echo "backend helper archive digest mismatch" >&2
  exit 66
}
tar -xf "${helper_archive}" -C "${artifact_root}/helper-context"
helper_source_dir=${artifact_root}/helper-context/${helper_path}
python3 "${archived_cert_dir}/verify_helper_input_manifest.py" \
  --manifest "${archived_pack_dir}/helper-input.sha256" \
  --helper-root "${helper_source_dir}" \
  --output "${artifact_root}/helper-input-verification.json"

dockerfile_sha256=$(sha256_file "${archived_pack_dir}/Dockerfile")
hash_set "${archived_pack_dir}" "${artifact_root}/source-lock-set.sha256" \
  apk-direct-packages.lock apk-packages.lock helper-input.lock.json helper-input.sha256 \
  requirements.in requirements.lock toolchain-manifest.json certification/tools.lock.json \
  policy/license-policy.json policy/license-review.lock.json policy/runtime-policy.json \
  policy/vex.lock.json policy/vulnerability-policy.json
lock_set_sha256=$(sha256_file "${artifact_root}/source-lock-set.sha256")
hash_set "${archived_pack_dir}" "${artifact_root}/conformance-set.sha256" \
  conformance/artifact_conformance.py conformance/finalize_receipt.py \
  conformance/materializer_conformance.py conformance/verify.sh
conformance_set_sha256=$(sha256_file "${artifact_root}/conformance-set.sha256")
hash_set "${archived_pack_dir}" "${artifact_root}/policy-set.sha256" \
  policy/license-policy.json policy/license-review.lock.json policy/runtime-policy.json \
  policy/vex.lock.json policy/vulnerability-policy.json
policy_set_sha256=$(sha256_file "${artifact_root}/policy-set.sha256")

helper_source_manifest_sha256=$(jq -er '.inputs.sourceManifestSha256' "${helper_lock}")
helper_build_lock_sha256=$(jq -er '.inputs.buildLockSha256' "${helper_lock}")
helper_binary_manifest_sha256=$(jq -er '.inputs.binaryManifestSha256' "${helper_lock}")
helper_binary_sha256=$(jq -er '.binary.sha256' "${helper_lock}")
helper_license_lock_sha256=$(jq -er '.inputs.licenseLockSha256' "${helper_lock}")
helper_notice_sha256=$(jq -er '.inputs.noticeSha256' "${helper_lock}")
helper_protocol_sha256=$(jq -er '.protocolSha256' "${helper_lock}")
helper_protocol_authority=$(jq -er '.atomicMaterializer.protocolAuthorityCommit' "${archived_pack_dir}/toolchain-manifest.json")
helper_provider_adapter=$(jq -er '.atomicMaterializer.providerAdapterCommit' "${archived_pack_dir}/toolchain-manifest.json")
helper_admission_fence=$(jq -er '.atomicMaterializer.admissionFenceCommit' "${archived_pack_dir}/toolchain-manifest.json")

expected_build_args=${artifact_root}/expected-build-args.json
jq -n -S \
  --arg source_revision "${source_revision}" \
  --arg source_date_epoch "${source_date_epoch}" \
  --arg source_tree "${source_tree}" \
  --arg source_pack_tree "${source_pack_tree}" \
  --arg source_input "${source_archive_sha256}" \
  --arg dockerfile "${dockerfile_sha256}" \
  --arg locks "${lock_set_sha256}" \
  --arg conformance "${conformance_set_sha256}" \
  --arg policy "${policy_set_sha256}" \
  --arg helper_revision "${helper_revision}" \
  --arg helper_tree "${helper_tree}" \
  --arg helper_archive "${helper_archive_sha256}" \
  --arg helper_source_manifest "${helper_source_manifest_sha256}" \
  --arg helper_build_lock "${helper_build_lock_sha256}" \
  --arg helper_binary_manifest "${helper_binary_manifest_sha256}" \
  --arg helper_binary "${helper_binary_sha256}" \
  --arg helper_license "${helper_license_lock_sha256}" \
  --arg helper_notice "${helper_notice_sha256}" \
  --arg protocol_authority "${helper_protocol_authority}" \
  --arg provider_adapter "${helper_provider_adapter}" \
  --arg admission_fence "${helper_admission_fence}" \
  '{
    "build-arg:SOURCE_DATE_EPOCH":$source_date_epoch,
    "build-arg:BUILD_SOURCE_REVISION":$source_revision,
    "build-arg:BUILD_SOURCE_TREE":$source_tree,
    "build-arg:BUILD_SOURCE_PACK_TREE":$source_pack_tree,
    "build-arg:BUILD_SOURCE_INPUT_SHA256":$source_input,
    "build-arg:BUILD_DOCKERFILE_SHA256":$dockerfile,
    "build-arg:BUILD_LOCK_SET_SHA256":$locks,
    "build-arg:BUILD_CONFORMANCE_SET_SHA256":$conformance,
    "build-arg:BUILD_POLICY_SET_SHA256":$policy,
    "build-arg:BUILD_HELPER_SOURCE_REVISION":$helper_revision,
    "build-arg:BUILD_HELPER_SOURCE_TREE":$helper_tree,
    "build-arg:BUILD_HELPER_SOURCE_ARCHIVE_SHA256":$helper_archive,
    "build-arg:BUILD_HELPER_SOURCE_MANIFEST_SHA256":$helper_source_manifest,
    "build-arg:BUILD_HELPER_BUILD_LOCK_SHA256":$helper_build_lock,
    "build-arg:BUILD_HELPER_BINARY_MANIFEST_SHA256":$helper_binary_manifest,
    "build-arg:BUILD_HELPER_BINARY_SHA256":$helper_binary,
    "build-arg:BUILD_HELPER_LICENSE_LOCK_SHA256":$helper_license,
    "build-arg:BUILD_HELPER_NOTICE_SHA256":$helper_notice,
    "build-arg:BUILD_HELPER_PROTOCOL_AUTHORITY_REVISION":$protocol_authority,
    "build-arg:BUILD_HELPER_PROVIDER_ADAPTER_REVISION":$provider_adapter,
    "build-arg:BUILD_HELPER_ADMISSION_FENCE_REVISION":$admission_fence
  }' > "${expected_build_args}"

expected_labels=${artifact_root}/expected-labels.json
jq -n -S \
  --arg source_revision "${source_revision}" --arg source_date_epoch "${source_date_epoch}" --arg source_tree "${source_tree}" \
  --arg source_pack_tree "${source_pack_tree}" --arg source_input "${source_archive_sha256}" \
  --arg dockerfile "${dockerfile_sha256}" --arg locks "${lock_set_sha256}" \
  --arg conformance "${conformance_set_sha256}" --arg policy "${policy_set_sha256}" \
  --arg helper_revision "${helper_revision}" --arg helper_tree "${helper_tree}" \
  --arg helper_archive "${helper_archive_sha256}" --arg helper_source_manifest "${helper_source_manifest_sha256}" \
  --arg helper_build_lock "${helper_build_lock_sha256}" --arg helper_binary_manifest "${helper_binary_manifest_sha256}" \
  --arg helper_binary "${helper_binary_sha256}" --arg helper_license "${helper_license_lock_sha256}" \
  --arg helper_notice "${helper_notice_sha256}" --arg protocol_authority "${helper_protocol_authority}" \
  --arg provider_adapter "${helper_provider_adapter}" --arg admission_fence "${helper_admission_fence}" \
  --arg helper_protocol "${helper_protocol_sha256}" \
  '{
    "org.opencontainers.image.revision":$source_revision,
    "io.ambit.source-date-epoch":$source_date_epoch,
    "io.ambit.source-tree":$source_tree,
    "io.ambit.source-pack-tree":$source_pack_tree,
    "io.ambit.build-input-sha256":$source_input,
    "io.ambit.dockerfile-sha256":$dockerfile,
    "io.ambit.lock-set-sha256":$locks,
    "io.ambit.conformance-set-sha256":$conformance,
    "io.ambit.policy-set-sha256":$policy,
    "io.ambit.helper-source-revision":$helper_revision,
    "io.ambit.helper-source-tree":$helper_tree,
    "io.ambit.helper-source-archive-sha256":$helper_archive,
    "io.ambit.helper-source-manifest-sha256":$helper_source_manifest,
    "io.ambit.helper-build-lock-sha256":$helper_build_lock,
    "io.ambit.helper-binary-manifest-sha256":$helper_binary_manifest,
    "io.ambit.helper-binary-sha256":$helper_binary,
    "io.ambit.helper-license-lock-sha256":$helper_license,
    "io.ambit.helper-notice-sha256":$helper_notice,
    "io.ambit.helper-protocol-authority-revision":$protocol_authority,
    "io.ambit.helper-provider-adapter-revision":$provider_adapter,
    "io.ambit.helper-admission-fence-revision":$admission_fence,
    "io.ambit.runtime-pack":"ambit.runtime-pack/core-document@3",
    "io.ambit.atomic-materializer-sha256":("sha256:" + $helper_binary),
    "io.ambit.atomic-materializer-license":"LicenseRef-Ambit-Proprietary",
    "io.ambit.atomic-materializer-protocol":("sha256:" + $helper_protocol)
  }' > "${expected_labels}"

tools_lock=${archived_cert_dir}/tools.lock.json
buildkit=$(jq -er '.buildkit' "${tools_lock}")
sbom_generator=$(jq -er '.buildkitSbomGenerator' "${tools_lock}")
grype=$(jq -er '.grype' "${tools_lock}")
registry=$(jq -er '.registry' "${tools_lock}")
wolfi=$(jq -er '.wolfiFilesystemReader' "${tools_lock}")
expected_materials=${artifact_root}/expected-materials.json
jq -n -S \
  --arg wolfi "sha256:$(jq -er '.baseImage' "${archived_pack_dir}/toolchain-manifest.json" | sed 's/^.*@sha256://')" \
  --arg go "sha256:$(jq -er '.materializerBuilderImage' "${archived_pack_dir}/toolchain-manifest.json" | sed 's/^.*@sha256://')" \
  --arg sbom "sha256:${sbom_generator##*@sha256:}" \
  '[
    {uri:"pkg:docker/cgr.dev/chainguard/wolfi-base",digest:$wolfi},
    {uri:"pkg:docker/golang",digest:$go},
    {uri:"pkg:docker/docker/buildkit-syft-scanner",digest:$sbom}
  ] | sort_by(.uri)' > "${expected_materials}"

daemon_log=${artifact_root}/transport/daytona-pty-tests.log
daemon_source_manifest=${artifact_root}/transport/daytona-pty-source.sha256
(
  cd "${repo_root}"
  find apps/daemon/pkg/toolbox/process/pty -maxdepth 1 -type f -name '*.go' -print0 \
    | LC_ALL=C sort -z | xargs -0 sha256sum
) > "${daemon_source_manifest}"
daemon_go_version=$(go version)
(
  cd "${repo_root}/apps/daemon"
  GOTOOLCHAIN=local go test -buildvcs=false -count=1 ./pkg/toolbox/process/pty
) > "${daemon_log}" 2>&1
jq -n -S --arg revision "${source_revision}" --arg tree "${source_tree}" \
  --arg go "${daemon_go_version}" --arg log "$(sha256_file "${daemon_log}")" \
  --arg source "$(sha256_file "${daemon_source_manifest}")" \
  '{schema:"ambit.daytona-pty-transport-test/v1",outcome:"passed",sourceRevision:$revision,sourceTree:$tree,command:"go test -buildvcs=false -count=1 ./pkg/toolbox/process/pty",goVersion:$go,logSha256:$log,sourceManifestSha256:$source}' \
  > "${artifact_root}/transport/daytona-pty-receipt.json"

cp -- "${provider_adapter_receipt}" "${artifact_root}/transport/provider-adapter-receipt.json"
cp -- "${provider_adapter_log}" "${artifact_root}/transport/$(basename "${provider_adapter_log}")"
python3 "${archived_cert_dir}/verify_provider_adapter_receipt.py" \
  --receipt "${artifact_root}/transport/provider-adapter-receipt.json" \
  --raw-log "${artifact_root}/transport/$(basename "${provider_adapter_log}")" \
  --backend-repo "${backend_repo}" --helper-lock "${helper_lock}" \
  --toolchain-manifest "${archived_pack_dir}/toolchain-manifest.json" \
  --output "${artifact_root}/transport/provider-adapter-verification.json"

registry_port=$(python3 - <<'PY'
import socket

with socket.socket() as listener:
    listener.bind(("127.0.0.1", 0))
    print(listener.getsockname()[1])
PY
)
[[ ${registry_port} =~ ^[0-9]+$ ]] || { echo "could not select task-local registry port" >&2; exit 67; }
registry_host=127.0.0.1:${registry_port}
docker run -d --name "${registry_name}" --network host \
  -e "REGISTRY_HTTP_ADDR=${registry_host}" \
  -v "${artifact_root}/registry-data:/var/lib/registry" "${registry}" >/dev/null
for _ in $(seq 1 100); do
  curl -fsS "http://${registry_host}/v2/" >/dev/null 2>&1 && break
  sleep 0.1
done
curl -fsS "http://${registry_host}/v2/" >/dev/null

repository=ambit/runtime-pack-core-document
source_short=${source_revision:0:12}
candidate_ref=${registry_host}/${repository}:candidate-${source_short}
docker buildx create --name "${builder_name}" --driver docker-container \
  --driver-opt "image=${buildkit},network=host" >/dev/null
docker buildx inspect --bootstrap "${builder_name}" >/dev/null

build_arguments=()
while IFS=$'\t' read -r key value; do
  build_arguments+=(--build-arg "${key#build-arg:}=${value}")
done < <(jq -r 'to_entries[] | [.key,.value] | @tsv' "${expected_build_args}")
docker buildx build --builder "${builder_name}" --network host --platform linux/amd64 --no-cache \
  --provenance=mode=max --attest="type=sbom,generator=${sbom_generator}" \
  --build-context "materializer_source=${helper_source_dir}" \
  "${build_arguments[@]}" \
  --output "type=image,name=${candidate_ref},push=true,rewrite-timestamp=true" \
  "${archived_pack_dir}"

registry_url=http://${registry_host}/v2/${repository}
curl -fsS -H 'Accept: application/vnd.oci.image.index.v1+json' \
  -o "${artifact_root}/oci/index.json" "${registry_url}/manifests/candidate-${source_short}"
index_digest=sha256:$(sha256_file "${artifact_root}/oci/index.json")
runtime_manifest=$(jq -er \
  '[.manifests[] | select(.platform.os == "linux" and .platform.architecture == "amd64")] | if length == 1 then .[0].digest else error("expected exactly one linux/amd64 runtime manifest") end' \
  "${artifact_root}/oci/index.json")
attestation_manifest=$(jq -er \
  '[.manifests[] | select(.annotations["vnd.docker.reference.type"] == "attestation-manifest")] | if length == 1 then .[0].digest else error("expected exactly one attestation manifest") end' \
  "${artifact_root}/oci/index.json")
curl -fsS -H 'Accept: application/vnd.oci.image.manifest.v1+json' \
  -o "${artifact_root}/oci/runtime-manifest.json" "${registry_url}/manifests/${runtime_manifest}"
curl -fsS -H 'Accept: application/vnd.oci.image.manifest.v1+json' \
  -o "${artifact_root}/oci/attestation-manifest.json" "${registry_url}/manifests/${attestation_manifest}"
config_digest=$(jq -er '.config.digest' "${artifact_root}/oci/runtime-manifest.json")
curl -fsS -o "${artifact_root}/oci/config.json" "${registry_url}/blobs/${config_digest}"
sbom_layer=$(jq -er \
  '[.layers[] | select(.annotations["in-toto.io/predicate-type"] == "https://spdx.dev/Document")] | if length == 1 then .[0].digest else error("expected exactly one SPDX attestation layer") end' \
  "${artifact_root}/oci/attestation-manifest.json")
provenance_layer=$(jq -er \
  '[.layers[] | select(.annotations["in-toto.io/predicate-type"] == "https://slsa.dev/provenance/v1")] | if length == 1 then .[0].digest else error("expected exactly one provenance attestation layer") end' \
  "${artifact_root}/oci/attestation-manifest.json")
curl -fsS -o "${artifact_root}/oci/sbom.intoto.json" "${registry_url}/blobs/${sbom_layer}"
curl -fsS -o "${artifact_root}/oci/provenance.intoto.json" "${registry_url}/blobs/${provenance_layer}"
jq '.predicate' "${artifact_root}/oci/sbom.intoto.json" > "${artifact_root}/oci/sbom.spdx.json"

reproduction_ref=${registry_host}/${repository}:reproduction-${source_short}
docker buildx build --builder "${builder_name}" --network host --platform linux/amd64 \
  --no-cache --provenance=false \
  --build-context "materializer_source=${helper_source_dir}" \
  "${build_arguments[@]}" \
  --output "type=image,name=${reproduction_ref},push=true,rewrite-timestamp=true" \
  "${archived_pack_dir}"
curl -fsS \
  -H 'Accept: application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json' \
  -o "${artifact_root}/oci/reproduction-reference.json" \
  "${registry_url}/manifests/reproduction-${source_short}"
reproduction_media_type=$(jq -er '.mediaType' "${artifact_root}/oci/reproduction-reference.json")
case "${reproduction_media_type}" in
  application/vnd.oci.image.index.v1+json)
    jq -e '
      .schemaVersion == 2 and
      (.manifests | type == "array" and length == 1) and
      .manifests[0].mediaType == "application/vnd.oci.image.manifest.v1+json" and
      .manifests[0].platform == {architecture:"amd64",os:"linux"} and
      (.manifests[0].digest | test("^sha256:[0-9a-f]{64}$"))
    ' "${artifact_root}/oci/reproduction-reference.json" >/dev/null
    reproduction_manifest=$(jq -er '.manifests[0].digest' "${artifact_root}/oci/reproduction-reference.json")
    curl -fsS -H 'Accept: application/vnd.oci.image.manifest.v1+json' \
      -o "${artifact_root}/oci/reproduction-manifest.json" \
      "${registry_url}/manifests/${reproduction_manifest}"
    ;;
  application/vnd.oci.image.manifest.v1+json)
    cp -- "${artifact_root}/oci/reproduction-reference.json" \
      "${artifact_root}/oci/reproduction-manifest.json"
    reproduction_manifest=sha256:$(sha256_file "${artifact_root}/oci/reproduction-manifest.json")
    ;;
  *)
    echo "reproduction reference has unsupported media type: ${reproduction_media_type}" >&2
    exit 68
    ;;
esac
jq -e '
  .schemaVersion == 2 and
  .mediaType == "application/vnd.oci.image.manifest.v1+json" and
  (.config.mediaType == "application/vnd.oci.image.config.v1+json") and
  (.config.digest | test("^sha256:[0-9a-f]{64}$")) and
  (.layers | type == "array" and length > 0) and
  all(.layers[];
    .mediaType == "application/vnd.oci.image.layer.v1.tar+gzip" and
    (.digest | test("^sha256:[0-9a-f]{64}$")) and
    (.size | type == "number" and . > 0)
  )
' "${artifact_root}/oci/reproduction-manifest.json" >/dev/null
[[ "sha256:$(sha256_file "${artifact_root}/oci/reproduction-manifest.json")" == "${reproduction_manifest}" ]] || {
  echo "reproduction manifest bytes differ from their selected digest" >&2
  exit 68
}
reproduction_config=$(jq -er '.config.digest' "${artifact_root}/oci/reproduction-manifest.json")
curl -fsS -o "${artifact_root}/oci/reproduction-config.json" \
  "${registry_url}/blobs/${reproduction_config}"
[[ "sha256:$(sha256_file "${artifact_root}/oci/reproduction-config.json")" == "${reproduction_config}" ]] || {
  echo "reproduction config bytes differ from their selected digest" >&2
  exit 68
}
jq -e '.architecture == "amd64" and .os == "linux"' \
  "${artifact_root}/oci/reproduction-config.json" >/dev/null
[[ ${reproduction_manifest} == "${runtime_manifest}" ]] || {
  echo "no-cache rebuild produced a different runtime manifest" >&2
  exit 68
}
jq -n -S --arg source "${source_revision}" --arg runtime "${runtime_manifest}" \
  --arg first "${index_digest}" \
  --arg reproduction_reference "sha256:$(sha256_file "${artifact_root}/oci/reproduction-reference.json")" \
  --arg reproduction_media "${reproduction_media_type}" \
  --arg reproduction_config "${reproduction_config}" \
  '{schema:"ambit.runtime-pack-reproducibility/v2",outcome:"passed",sourceRevision:$source,runtimeManifestDigest:$runtime,attestedIndexDigest:$first,reproductionReferenceDigest:$reproduction_reference,reproductionReferenceMediaType:$reproduction_media,reproductionConfigDigest:$reproduction_config,builds:{attested:"no-cache-rewrite-timestamp",reproduction:"no-cache-rewrite-timestamp-without-attestation"}}' \
  > "${artifact_root}/reproducibility-receipt.json"

python3 "${archived_cert_dir}/verify_attestations.py" "${artifact_root}/oci" \
  --index "${index_digest}" --manifest "${runtime_manifest}" --config "${config_digest}" \
  --attestation-manifest "${attestation_manifest}" --sbom-layer "${sbom_layer}" \
  --provenance-layer "${provenance_layer}" --expected-labels "${expected_labels}" \
  --expected-build-args "${expected_build_args}" --expected-materials "${expected_materials}" \
  --output "${artifact_root}/attestation-verification.json"

runtime_ref=${registry_host}/${repository}@${runtime_manifest}
docker pull --platform linux/amd64 "${runtime_ref}" >/dev/null
docker image inspect "${runtime_ref}" > "${artifact_root}/runtime-image-inspect.json"
[[ $(jq -er '.[0].Id' "${artifact_root}/runtime-image-inspect.json") == "${config_digest}" ]] || {
  echo "pulled runtime config does not match OCI runtime manifest" >&2
  exit 68
}
docker save -o "${artifact_root}/runtime-image.tar" "${runtime_ref}"
python3 "${archived_cert_dir}/scan_image_secrets.py" "${artifact_root}/runtime-image.tar" \
  --output "${artifact_root}/security/image-secret-scan.json"
[[ $(jq -er '.input.configSha256' "${artifact_root}/security/image-secret-scan.json") == "${config_digest#sha256:}" ]] || {
  echo "image secret scan did not inspect the exact OCI config" >&2
  exit 68
}

docker_run_base=(
  --rm --network none --cap-drop ALL --security-opt no-new-privileges:true --read-only
  --pids-limit 512 --memory 4g
  --tmpfs /tmp:rw,nosuid,nodev,size=1g,mode=1777
  --tmpfs /run:rw,nosuid,nodev,size=64m,mode=0755
  --tmpfs /workspace:rw,nosuid,nodev,size=256m,mode=0755,uid=1000,gid=1000
  -v "${archived_pack_dir}:/pack-source:ro"
  -v "${helper_source_dir}:/helper-source:ro"
)
conformance_dir=${artifact_root}/conformance
mkdir -p "${conformance_dir}"
chmod 0777 "${conformance_dir}"
docker run "${docker_run_base[@]}" -v "${conformance_dir}:/evidence:rw" --entrypoint /bin/bash \
  "${runtime_ref}" /pack-source/conformance/verify.sh /evidence /pack-source /helper-source

run_negative_conformance() {
  local name=$1
  local expected_status=$2
  local expected_log=$3
  shift 3
  local output_dir=${artifact_root}/conformance-negative-${name}
  local log=${artifact_root}/negative-${name}.log
  mkdir -p "${output_dir}"
  chmod 0777 "${output_dir}"
  set +e
  docker run "${docker_run_base[@]}" "$@" -v "${output_dir}:/evidence:rw" --entrypoint /bin/bash \
    "${runtime_ref}" /pack-source/conformance/verify.sh /evidence /pack-source /helper-source >"${log}" 2>&1
  local status=$?
  set -e
  [[ ${status} -eq ${expected_status} ]] || { echo "${name} negative gate returned ${status}" >&2; exit 69; }
  grep -F "${expected_log}" "${log}" >/dev/null
  [[ ! -e ${output_dir}/conformance-receipt.json ]] || { echo "${name} negative gate wrote success" >&2; exit 69; }
  jq -n -S --arg gate "${name}" --argjson expected "${expected_status}" --argjson actual "${status}" \
    --arg log "$(sha256_file "${log}")" \
    '{schema:"ambit.runtime-pack-negative-gate/v1",outcome:"passed",gate:$gate,expectedExitCode:$expected,actualExitCode:$actual,logSha256:$log}' \
    > "${artifact_root}/negative-${name}-receipt.json"
}
run_negative_conformance root 91 'runtime-user-gate: expected uid 1000 user daytona' --user root
run_negative_conformance secret-env 1 'secret-shaped environment variable reached the runtime' \
  -e AMBIT_TEST_SECRET=deliberately-non-secret-sentinel

socket_fixture=${artifact_root}/docker-socket-fixture.sock
socket_ready=${artifact_root}/docker-socket-fixture.ready
python3 - "${socket_fixture}" "${socket_ready}" <<'PY' &
import os
import signal
import socket
import sys

server = socket.socket(socket.AF_UNIX)
server.bind(sys.argv[1])
os.chmod(sys.argv[1], 0o666)
open(sys.argv[2], "x").close()
signal.pause()
PY
socket_pid=$!
for _ in $(seq 1 100); do [[ -S ${socket_fixture} && -e ${socket_ready} ]] && break; sleep 0.05; done
[[ -S ${socket_fixture} && -e ${socket_ready} ]] || { echo "socket fixture failed" >&2; exit 69; }
run_negative_conformance socket 92 'host-socket-gate: /var/run/docker.sock is forbidden' \
  --mount "type=bind,src=${socket_fixture},dst=/var/run/docker.sock,readonly"
kill "${socket_pid}"
wait "${socket_pid}" >/dev/null 2>&1 || true
socket_pid=
unlink "${socket_fixture}"
unlink "${socket_ready}"
socket_fixture=

set +e
docker run "${docker_run_base[@]}" --entrypoint /bin/bash "${runtime_ref}" \
  /pack-source/certification/verify_runtime_installer_absence.sh \
  > "${artifact_root}/negative-install-script.log" 2>&1
install_status=$?
set -e
[[ ${install_status} -eq 93 ]] || { echo "installer absence negative gate failed" >&2; exit 69; }
jq -n -S --argjson status "${install_status}" --arg log "$(sha256_file "${artifact_root}/negative-install-script.log")" \
  '{schema:"ambit.runtime-pack-negative-gate/v1",outcome:"passed",gate:"malicious-install-script-unavailable",actualExitCode:$status,logSha256:$log}' \
  > "${artifact_root}/negative-install-script-receipt.json"

wolfi_spdx_dir=${artifact_root}/vex-primary/wolfi-sboms
mkdir -p "${wolfi_spdx_dir}"
chmod 0777 "${wolfi_spdx_dir}"
docker run "${docker_run_base[@]}" -v "${wolfi_spdx_dir}:/wolfi-evidence:rw" --entrypoint /bin/bash \
  "${runtime_ref}" -ceu 'cp /var/lib/db/sbom/glibc-2.43-2.43-r14.spdx.json /wolfi-evidence/; cp /var/lib/db/sbom/libcrypto3-3.6.3-r5.spdx.json /wolfi-evidence/; cp /var/lib/db/sbom/libssl3-3.6.3-r5.spdx.json /wolfi-evidence/; chmod 0644 /wolfi-evidence/*.json'

cp -- "${vex_evidence_dir}/glibc-2.43.yaml" "${artifact_root}/vex-primary/glibc-2.43.yaml"
cp -- "${vex_evidence_dir}/openssl.yaml" "${artifact_root}/vex-primary/openssl.yaml"
cp -- "${vex_evidence_dir}/CVE-2019-1010022.html" "${artifact_root}/vex-primary/CVE-2019-1010022.html"
cp -- "${vex_evidence_dir}/CVE-2019-1010023.html" "${artifact_root}/vex-primary/CVE-2019-1010023.html"
cp -- "${vex_evidence_dir}/sourceware-bug-22850.json" "${artifact_root}/vex-primary/sourceware-bug-22850.json"
cp -- "${vex_evidence_dir}/sourceware-bug-22851.json" "${artifact_root}/vex-primary/sourceware-bug-22851.json"

jq -n -S --arg runtime "${runtime_manifest}" \
  --argjson glibc "$(jq -n --arg name glibc-2.43-2.43-r14.spdx.json --argjson bytes "$(stat -c %s "${wolfi_spdx_dir}/glibc-2.43-2.43-r14.spdx.json")" --arg sha "$(sha256_file "${wolfi_spdx_dir}/glibc-2.43-2.43-r14.spdx.json")" '{name:$name,bytes:$bytes,sha256:$sha}')" \
  --argjson libcrypto "$(jq -n --arg name libcrypto3-3.6.3-r5.spdx.json --argjson bytes "$(stat -c %s "${wolfi_spdx_dir}/libcrypto3-3.6.3-r5.spdx.json")" --arg sha "$(sha256_file "${wolfi_spdx_dir}/libcrypto3-3.6.3-r5.spdx.json")" '{name:$name,bytes:$bytes,sha256:$sha}')" \
  --argjson libssl "$(jq -n --arg name libssl3-3.6.3-r5.spdx.json --argjson bytes "$(stat -c %s "${wolfi_spdx_dir}/libssl3-3.6.3-r5.spdx.json")" --arg sha "$(sha256_file "${wolfi_spdx_dir}/libssl3-3.6.3-r5.spdx.json")" '{name:$name,bytes:$bytes,sha256:$sha}')" \
  '{schema:"ambit.runtime-pack-wolfi-package-evidence/v1",outcome:"passed",runtimeManifestDigest:$runtime,files:{glibc:$glibc,libcrypto:$libcrypto,libssl:$libssl}}' \
  > "${artifact_root}/vex-primary/package-evidence-receipt.json"

docker run --rm --network none --entrypoint /bin/sh \
  -v "${grype_cache}:/cache:ro" "${wolfi}" -ceu \
  'cd /cache; find . -type f -print | LC_ALL=C sort | while IFS= read -r file; do sha256sum "$file"; done' \
  > "${artifact_root}/security/grype-db-files.sha256"
grype_db_tree=$(sha256_file "${artifact_root}/security/grype-db-files.sha256")
[[ ${grype_db_tree} == "${grype_expected_tree}" ]] || { echo "Grype DB tree digest mismatch" >&2; exit 70; }

docker run --rm --network none \
  -e GRYPE_CHECK_FOR_APP_UPDATE=false -e GRYPE_DB_AUTO_UPDATE=false \
  -v "${artifact_root}/oci:/input:ro" -v "${artifact_root}/security:/output" -v "${grype_cache}:/cache:ro" \
  "${grype}" sbom:/input/sbom.spdx.json -o json --file /output/vulnerability.grype.json
grype_database=$(jq -c '.descriptor.db.status' "${artifact_root}/security/vulnerability.grype.json")
jq -n -S --arg tree "${grype_db_tree}" --arg manifest "$(sha256_file "${artifact_root}/security/grype-db-files.sha256")" \
  --argjson database "${grype_database}" \
  '{schema:"ambit.runtime-pack-grype-database/v1",outcome:"passed",treeSha256:$tree,fileManifestSha256:$manifest,database:$database}' \
  > "${artifact_root}/security/grype-db-receipt.json"

python3 "${archived_cert_dir}/verify_vex_evidence.py" \
  --vex "${archived_policy_dir}/vex.lock.json" \
  --conformance-receipt "${conformance_dir}/conformance-receipt.json" \
  --actual-apk-lock "${conformance_dir}/apk-packages.actual.lock" \
  --vulnerabilities "${artifact_root}/security/vulnerability.grype.json" \
  --grype-db-receipt "${artifact_root}/security/grype-db-receipt.json" \
  --package-evidence-receipt "${artifact_root}/vex-primary/package-evidence-receipt.json" \
  --glibc-package-spdx "${wolfi_spdx_dir}/glibc-2.43-2.43-r14.spdx.json" \
  --libcrypto-package-spdx "${wolfi_spdx_dir}/libcrypto3-3.6.3-r5.spdx.json" \
  --libssl-package-spdx "${wolfi_spdx_dir}/libssl3-3.6.3-r5.spdx.json" \
  --glibc-build-config "${artifact_root}/vex-primary/glibc-2.43.yaml" \
  --openssl-build-config "${artifact_root}/vex-primary/openssl.yaml" \
  --cve-2019-1010022-authority "${artifact_root}/vex-primary/CVE-2019-1010022.html" \
  --cve-2019-1010023-authority "${artifact_root}/vex-primary/CVE-2019-1010023.html" \
  --cve-2019-1010022-upstream "${artifact_root}/vex-primary/sourceware-bug-22850.json" \
  --cve-2019-1010023-upstream "${artifact_root}/vex-primary/sourceware-bug-22851.json" \
  --glibc-git-dir "${glibc_git_dir}" --openssl-git-dir "${openssl_git_dir}" \
  --output "${artifact_root}/vex-evidence-verification.json"

policy_args=(
  --sbom "${artifact_root}/oci/sbom.spdx.json"
  --vulnerabilities "${artifact_root}/security/vulnerability.grype.json"
  --license-policy "${archived_policy_dir}/license-policy.json"
  --license-review "${archived_policy_dir}/license-review.lock.json"
  --vulnerability-policy "${archived_policy_dir}/vulnerability-policy.json"
  --vex "${archived_policy_dir}/vex.lock.json"
  --vex-verification "${artifact_root}/vex-evidence-verification.json"
)
python3 "${archived_cert_dir}/policy_gate.py" "${policy_args[@]}" \
  --output "${artifact_root}/policy-gate.json" --allow-failed-output

signing_dir=$(mktemp -d "${artifact_root}.signing.XXXXXX")
private_key=${signing_dir}/private-key.pem
umask 077
openssl genpkey -algorithm ED25519 -out "${private_key}"
openssl pkey -in "${private_key}" -pubout -out "${artifact_root}/public-signing-key.pem"
openssl pkey -pubin -in "${artifact_root}/public-signing-key.pem" -outform DER \
  -out "${artifact_root}/public-signing-key.der"
umask 022

policy_outcome=$(jq -er '.outcome' "${artifact_root}/policy-gate.json")
public_pem_sha256=$(sha256_file "${artifact_root}/public-signing-key.pem")
public_der_sha256=$(sha256_file "${artifact_root}/public-signing-key.der")
jq -n -S \
  --arg outcome "${policy_outcome}" --arg source_revision "${source_revision}" \
  --arg source_tree "${source_tree}" --arg source_pack_tree "${source_pack_tree}" \
  --arg source_archive "${source_archive_sha256}" --arg helper_revision "${helper_revision}" \
  --arg helper_tree "${helper_tree}" --arg helper_archive "${helper_archive_sha256}" \
  --arg helper_binary "${helper_binary_sha256}" --arg protocol "${helper_protocol_sha256}" \
  --arg adapter "${helper_provider_adapter}" --arg admission_fence "${helper_admission_fence}" \
  --arg index "${index_digest}" --arg manifest "${runtime_manifest}" --arg config "${config_digest}" \
  --arg attestation_manifest "${attestation_manifest}" --arg sbom_layer "${sbom_layer}" \
  --arg provenance_layer "${provenance_layer}" \
  --arg attestation "$(sha256_file "${artifact_root}/attestation-verification.json")" \
  --arg helper_input_verification "$(sha256_file "${artifact_root}/helper-input-verification.json")" \
  --arg reproducibility "$(sha256_file "${artifact_root}/reproducibility-receipt.json")" \
  --arg conformance "$(sha256_file "${conformance_dir}/conformance-receipt.json")" \
  --arg materializer "$(sha256_file "${conformance_dir}/materializer-receipt.json")" \
  --arg artifacts "$(sha256_file "${conformance_dir}/artifact-receipt.json")" \
  --arg daemon "$(sha256_file "${artifact_root}/transport/daytona-pty-receipt.json")" \
  --arg provider "$(sha256_file "${artifact_root}/transport/provider-adapter-receipt.json")" \
  --arg provider_log "$(sha256_file "${artifact_root}/transport/$(basename "${provider_adapter_log}")")" \
  --arg provider_verification "$(sha256_file "${artifact_root}/transport/provider-adapter-verification.json")" \
  --arg vex_verification "$(sha256_file "${artifact_root}/vex-evidence-verification.json")" \
  --arg vulnerability "$(sha256_file "${artifact_root}/security/vulnerability.grype.json")" \
  --arg db "$(sha256_file "${artifact_root}/security/grype-db-receipt.json")" \
  --arg secret_scan "$(sha256_file "${artifact_root}/security/image-secret-scan.json")" \
  --arg negative_root "$(sha256_file "${artifact_root}/negative-root-receipt.json")" \
  --arg negative_socket "$(sha256_file "${artifact_root}/negative-socket-receipt.json")" \
  --arg negative_secret "$(sha256_file "${artifact_root}/negative-secret-env-receipt.json")" \
  --arg negative_install "$(sha256_file "${artifact_root}/negative-install-script-receipt.json")" \
  --arg policy "$(sha256_file "${artifact_root}/policy-gate.json")" \
  --arg dockerfile "${dockerfile_sha256}" --arg locks "${lock_set_sha256}" \
  --arg conformance_set "${conformance_set_sha256}" --arg policy_set "${policy_set_sha256}" \
  --arg sbom "$(sha256_file "${artifact_root}/oci/sbom.spdx.json")" \
  --arg provenance "$(sha256_file "${artifact_root}/oci/provenance.intoto.json")" \
  --arg license_review "$(sha256_file "${archived_policy_dir}/license-review.lock.json")" \
  --arg vex "$(sha256_file "${archived_policy_dir}/vex.lock.json")" \
  --arg license_policy "$(sha256_file "${archived_policy_dir}/license-policy.json")" \
  --arg runtime_policy "$(sha256_file "${archived_policy_dir}/runtime-policy.json")" \
  --arg vulnerability_policy "$(sha256_file "${archived_policy_dir}/vulnerability-policy.json")" \
  --arg apk_direct "$(sha256_file "${archived_pack_dir}/apk-direct-packages.lock")" \
  --arg apk_closure "$(sha256_file "${archived_pack_dir}/apk-packages.lock")" \
  --arg python_lock "$(sha256_file "${archived_pack_dir}/requirements.lock")" \
  --arg helper_input_lock "$(sha256_file "${archived_pack_dir}/helper-input.lock.json")" \
  --arg helper_input_manifest "$(sha256_file "${archived_pack_dir}/helper-input.sha256")" \
  --arg toolchain "$(sha256_file "${archived_pack_dir}/toolchain-manifest.json")" \
  --arg tools "$(sha256_file "${tools_lock}")" --arg public_pem "${public_pem_sha256}" \
  --arg host_tools "$(sha256_file "${artifact_root}/certification-host-tools.json")" \
  --arg public_der "${public_der_sha256}" \
  '{
    schema:"ambit.runtime-pack-evidence-binding/v3",
    outcome:(if $outcome == "passed" then "candidate_policy_passed" else "candidate_policy_failed" end),
    packRef:"ambit.runtime-pack/core-document@3",platform:"linux/amd64",
    identity:{providerPullDigest:$index,runtimeCapabilityPackRevisionArtifactDigest:$manifest,configDigest:$config},
    source:{daytona:{revision:$source_revision,tree:$source_tree,packTree:$source_pack_tree,archiveSha256:$source_archive,dockerfileSha256:$dockerfile,lockSetSha256:$locks,conformanceSetSha256:$conformance_set,policySetSha256:$policy_set},backendHelper:{revision:$helper_revision,tree:$helper_tree,archiveSha256:$helper_archive,binarySha256:$helper_binary,protocolSha256:$protocol,providerAdapterRevision:$adapter,admissionFenceRevision:$admission_fence}},
    attestations:{manifestDigest:$attestation_manifest,sbomLayerDigest:$sbom_layer,provenanceLayerDigest:$provenance_layer,sbomSpdxSha256:$sbom,provenanceStatementSha256:$provenance},
    verification:{attestationReceiptSha256:$attestation,helperInputReceiptSha256:$helper_input_verification,reproducibilityReceiptSha256:$reproducibility,conformanceReceiptSha256:$conformance,materializerReceiptSha256:$materializer,artifactReceiptSha256:$artifacts,daytonaPtyReceiptSha256:$daemon,providerAdapterReceiptSha256:$provider,providerAdapterRawLogSha256:$provider_log,providerAdapterVerificationSha256:$provider_verification,vexEvidenceReceiptSha256:$vex_verification,vulnerabilityReportSha256:$vulnerability,grypeDatabaseReceiptSha256:$db,imageSecretScanSha256:$secret_scan,negativeRootReceiptSha256:$negative_root,negativeSocketReceiptSha256:$negative_socket,negativeSecretEnvReceiptSha256:$negative_secret,negativeInstallScriptReceiptSha256:$negative_install,policyReceiptSha256:$policy},
    sourceContracts:{apkDirectLockSha256:$apk_direct,apkClosureLockSha256:$apk_closure,pythonLockSha256:$python_lock,helperInputLockSha256:$helper_input_lock,helperInputManifestSha256:$helper_input_manifest,toolchainManifestSha256:$toolchain},
    policyInputs:{licensePolicySha256:$license_policy,licenseReviewSha256:$license_review,runtimePolicySha256:$runtime_policy,vexSha256:$vex,vulnerabilityPolicySha256:$vulnerability_policy,certificationToolsLockSha256:$tools,hostToolsReceiptSha256:$host_tools},
    signingKey:{algorithm:"Ed25519",publicKeyPemSha256:$public_pem,publicKeyDerSha256:$public_der},
    signatureMeaning:"ephemeral local evidence content binding only; not a production publisher identity",
    promotion:"separate-and-not-performed",
    limitations:["document.render@1 unavailable until C19 paginated renderer composes","CertifiedDocumentProfile and Document Skill v1 remain inactive","load cache and checkpoint SLOs not measured"]
  }' > "${artifact_root}/evidence-binding.json"

openssl pkeyutl -sign -rawin -inkey "${private_key}" -in "${artifact_root}/evidence-binding.json" \
  -out "${artifact_root}/evidence-binding.ed25519.sig"
openssl pkeyutl -verify -rawin -pubin -inkey "${artifact_root}/public-signing-key.pem" \
  -in "${artifact_root}/evidence-binding.json" -sigfile "${artifact_root}/evidence-binding.ed25519.sig"
jq -n -S --arg binding "$(sha256_file "${artifact_root}/evidence-binding.json")" \
  --arg signature "$(sha256_file "${artifact_root}/evidence-binding.ed25519.sig")" \
  --arg public_pem "${public_pem_sha256}" --arg public_der "${public_der_sha256}" \
  '{schema:"ambit.runtime-pack-evidence-signature/v1",outcome:"passed",algorithm:"Ed25519",bindingSha256:$binding,signatureSha256:$signature,publicKeyPemSha256:$public_pem,publicKeyDerSha256:$public_der}' \
  > "${artifact_root}/evidence-signature-verification.json"
shred -u -- "${private_key}" || unlink "${private_key}"
private_key=
rmdir "${signing_dir}"
signing_dir=

set +e
python3 "${archived_cert_dir}/policy_gate.py" "${policy_args[@]}" \
  --output "${artifact_root}/policy-gate-strict.json"
policy_status=$?
set -e
cmp "${artifact_root}/policy-gate.json" "${artifact_root}/policy-gate-strict.json"

(
  cd "${artifact_root}"
  find . -type f ! -path './registry-data/*' ! -name evidence-manifest.sha256 -print0 \
    | LC_ALL=C sort -z | while IFS= read -r -d '' file; do
        sha256sum "${file}"
      done
) > "${artifact_root}/evidence-manifest.sha256"

docker rm -f "${registry_name}" >/dev/null
registry_name=
docker run --rm --network none -v "${artifact_root}/registry-data:/data" --entrypoint /bin/sh \
  "${wolfi}" -ceu 'rm -rf -- /data/* /data/.[!.]* /data/..?*'
rmdir "${artifact_root}/registry-data"

if (( policy_status != 0 )); then
  echo "candidate evidence is signed, but promotion is refused because strict policy failed" >&2
  exit "${policy_status}"
fi
echo "candidate policy passed; promotion remains separate and Document profile activation remains blocked on C19"
