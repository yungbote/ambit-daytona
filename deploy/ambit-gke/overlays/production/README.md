<!--
Copyright 2026 Ambit
SPDX-License-Identifier: AGPL-3.0
-->

# Ambit Daytona production overlay

This overlay binds the provider-neutral Daytona base to Ambit's production GCP
dependencies. It adds native GKE Secret Sync, Workload Identity, Cloud SQL Auth
Proxy, separate authenticated in-cluster Redis instances for Daytona and
Harbor, distributed MinIO, a GCS-backed internal OCI registry, and a global
external GKE Gateway. Harbor supplies both that OCI registry and Daytona's
required robot account API; there is no second registry compatibility layer.
The overlay uses the platform-selected production address resource and
certificate map.

## Render and release gates

Kustomize does not allow a nested overlay to import its ancestor
Kustomization, so this overlay lists the base resource files explicitly. The
raw base carries `SOURCE_REVISION_REQUIRED`; do not invoke Kustomize directly
for an admitted production release. Render from the repository root with:

```sh
deploy/ambit-gke/overlays/production/render-production.sh > rendered.yaml
```

The renderer reads the four immutable Daytona manifests from Artifact Registry,
requires one canonical `org.opencontainers.image.source`, requires one shared
full `org.opencontainers.image.revision` that resolves to an exact Git commit,
and only then writes that revision into the five Daytona workload annotations.
It also rejects every unresolved input, mutable image, retired `daytona-oss-*`
repository, managed-Redis CA seam, or missing proxy apex/deep-wildcard route.

The exact official Harbor 1.19.2 chart is vendored under `charts/`; its archive
SHA-256 was verified against the official repository index and is recorded in
`harbor-values.yaml`. Every resulting Harbor 2.15.2 runtime image is further
pinned by digest. Harbor is deliberately not rendered by Kustomize: its chart
uses a live-cluster `lookup` to read the Secret Sync-managed cluster-local Redis
credential. Rendering it offline silently produces passwordless Redis URLs.

Before apply, the following command must return no output:

```sh
rg 'REQUIRED_|build-required|source-build-required|SOURCE_REVISION_REQUIRED' rendered.yaml
```

The admitted render enforces these release invariants:

- all four Daytona components use the current `daytona-*` Artifact Registry
  repositories and immutable digests produced from this public fork;
- the selected OIDC issuer, client ID, and audience stay tied to the identity
  boundary Ambit actually uses; and
- `DEFAULT_SNAPSHOT` stays on its immutable sandbox image digest.

The MinIO runtime reference is intended to be the Artifact Registry digest
built by `cloudbuild.minio.yaml` from public AGPL commit
`9e49d5e7a648f00e26f2246f4dc28e6b07f8c84a`. Immutability alone does not prove
that lineage: verify the digest exists and exposes the expected source labels
before apply. Do not replace it with an unverifiable prebuilt Community image.

Do **not** apply the complete render as one unsequenced operation. Kubernetes
does not wait for a Job merely because it appears earlier in a multi-document
file. The release controller must reconcile foundations and state first, then
run migrations and wait for completion before creating or updating API Pods.
Harbor and the HTTPS Gateway registry route must also be healthy before the API
bootstraps: the default snapshot is pulled by the runner and pushed through
`https://registry.daytona.ambit.sh`. The API pod has a
`wait-for-internal-registry` init container that accepts only a verified TLS
response of 200 or the expected unauthenticated 401 from `/v2/`; this prevents
an early Gateway race from persisting a general snapshot in `error` state.

On an empty Daytona database, run the checked-in `daytona-migrate` Job (which
uses `migration:run:init`) from the exact API image digest being released and
wait for it to complete before starting the API. On every later release, use a
release-specific Job with `migration:run:pre-deploy`, wait for it, roll out and
verify the new API, then use a second release-specific Job with
`migration:run:post-deploy`. Never run `migration:run:init` ahead of an existing
API: it includes contract migrations. A stable Kubernetes Job is immutable, so
the deployment controller must delete/recreate the completed bootstrap Job or
name each phased Job by release; it must never run two migration Jobs at once.

After Secret Sync has created all of
`daytona-harbor-admin`, `daytona-harbor-shared`, `daytona-harbor-xsrf`,
`daytona-harbor-token`, `daytona-harbor-registry-credentials`,
`daytona-harbor-db`, and `daytona-harbor-redis` in `daytona-state`, install
Harbor as a live Helm release. The repository-scoped Helm 4 post-renderer
applies the Cloud SQL Auth Proxy sidecars without copying the chart or its
generated resources back into Kustomize:

```sh
OVERLAY="$PWD/deploy/ambit-gke/overlays/production"
HELM_PLUGINS="$OVERLAY/helm-plugins" \
helm upgrade --install daytona-harbor "$OVERLAY/charts/harbor-1.19.2/harbor" \
  --namespace daytona-state \
  --values "$OVERLAY/harbor-values.yaml" \
  --post-renderer=ambit-harbor \
  --rollback-on-failure \
  --wait=watcher \
  --wait-for-jobs \
  --timeout 20m

kubectl apply -f "$OVERLAY/harbor-bootstrap.yaml"
kubectl wait --namespace daytona-state \
  --for=condition=complete job/daytona-harbor-bootstrap \
  --timeout=20m
```

Keep `HELM_PLUGINS` scoped to this command. The post-renderer plugin is checked
in at `helm-plugins/ambit-harbor`; using the executable path directly with
`--post-renderer` is Helm 3 syntax and does not work with Helm 4.

## Workload identity and secret access

The cluster must have GKE Secret Sync and 60-second rotation enabled. Secret
Sync authenticates as each Kubernetes ServiceAccount, so grant only the secret
set that service consumes. For the state identities added here:

```sh
PROJECT_ID=mwcc-infrastructure
PROJECT_NUMBER=411589140767
POOL="${PROJECT_ID}.svc.id.goog"

MINIO_PRINCIPAL="principal://iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/${POOL}/subject/ns/daytona-state/sa/daytona-minio"
for SECRET in ambit-daytona-minio-access-key ambit-daytona-minio-secret-key; do
  gcloud secrets add-iam-policy-binding "$SECRET" \
    --project "$PROJECT_ID" \
    --role roles/secretmanager.secretAccessor \
    --member "$MINIO_PRINCIPAL"
done

HARBOR_SECRET_PRINCIPAL="principal://iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/${POOL}/subject/ns/daytona-state/sa/daytona-harbor-secrets"
for SECRET in \
  ambit-daytona-registry-password \
  ambit-daytona-harbor-redis-auth \
  ambit-daytona-harbor-shared-secret \
  ambit-daytona-harbor-xsrf-key \
  ambit-daytona-harbor-token-key \
  ambit-daytona-harbor-token-cert \
  ambit-daytona-harbor-registry-htpasswd \
  ambit-daytona-harbor-db-password; do
  gcloud secrets add-iam-policy-binding "$SECRET" \
    --project "$PROJECT_ID" \
    --role roles/secretmanager.secretAccessor \
    --member "$HARBOR_SECRET_PRINCIPAL"
done

gcloud iam service-accounts add-iam-policy-binding \
  ambit-daytona-runtime@mwcc-infrastructure.iam.gserviceaccount.com \
  --project "$PROJECT_ID" \
  --role roles/iam.workloadIdentityUser \
  --member 'serviceAccount:mwcc-infrastructure.svc.id.goog[daytona-state/daytona-harbor-cloud]'
```

The runtime GSA needs object access to
`mwcc-ambit-daytona-registry-411589140767`; the API KSA uses the same GSA for
`roles/cloudsql.client`. Harbor core/exporter use loopback Cloud SQL Auth Proxy
sidecars, and Harbor registry uses GCS Application Default Credentials. No
long-lived Google service-account key is mounted.

Harbor adds genuine durable state contracts, not optional placeholders:

- `ambit-daytona-harbor-shared-secret`: exactly 16 random characters, used by
  Harbor's mutually trusted internal components;
- `ambit-daytona-harbor-xsrf-key`: exactly 32 random characters;
- `ambit-daytona-harbor-token-key` and
  `ambit-daytona-harbor-token-cert`: a durable PEM private key and matching
  certificate for registry token signing;
- `ambit-daytona-harbor-registry-htpasswd`: one bcrypt htpasswd line for the
  fixed internal user `harbor_registry_user`, derived from the current
  `ambit-daytona-registry-password` value;
- `ambit-daytona-harbor-db-password`: the password for a separate `harbor`
  Cloud SQL user and `harbor` database on the existing instance.

The existing `ambit-daytona-registry-admin` value was checked to be Harbor's
fixed `admin` username. The existing registry password becomes the Harbor
admin password and remains the credential Daytona stores. Create the separate
database/user before Harbor starts; sharing Daytona's `daytona` schema would
collapse unrelated ownership and is not supported.

The Harbor bootstrap Job authenticates directly to the registry with the raw
internal password before it creates or accepts the project. This proves the
derived htpasswd line matches the password Secret; a syntactically valid but
stale bcrypt line therefore fails deployment instead of surfacing later as an
image-push error.

`DB_USERNAME=daytona`, `REDIS_USERNAME=default`, and the probe-only health key
are non-secret runtime configuration. The production Redis passwords, database
password, encryption material, API keys, SSH keys, registry credentials, and
MinIO root credentials all originate in Secret Manager.

Secret Sync updates Kubernetes Secret objects when `latest` changes. The
current Daytona processes consume most values through environment variables
and do not hot-reload them, so a controlled workload rollout is still required
after rotation. SSH host-key and MinIO/registry credential rotation also
requires an overlap or coordinated cutover; do not treat the 60-second sync as
application-level rotation by itself.

## State services

`redis.yaml` owns two retained, authenticated Redis 7.4 instances. Daytona API
and proxy share `daytona-system/redis` and the existing
`ambit-daytona-redis-auth` secret; Harbor owns
`daytona-state/harbor-redis` and `ambit-daytona-harbor-redis-auth`. Both use
10 GiB retained `daytona-standard-rwo` claims, digest-pinned images, restricted
pod security, authenticated health checks, and namespace-local ingress. They
are single-replica services and therefore do not claim Redis high availability.
The move removes managed-Redis TLS and CA distribution without removing
password authentication.

Daytona's object-storage service calls MinIO's
`/minio/v1/assume-role` endpoint and hands one-hour, organization-prefix-scoped
credentials to runners. GCS alone does not implement that contract. The
overlay therefore runs four MinIO peers on separate retained
`daytona-standard-rwo` volumes and creates the shared `ambit-daytona` bucket
with a pinned `mc` job. The bootstrap Job, API, and runners use the
cluster-local MinIO Service, so owned state and control-plane startup do not
depend on public DNS, certificates, or the Gateway. The public MinIO route is
an edge endpoint, not an internal service-discovery dependency.

The official Harbor 2.15.2 deployment owns both Daytona registry roles at
`https://registry.daytona.ambit.sh`. Its registry uses GCS through Workload
Identity; redirects are disabled, avoiding a separate `signBlob` permission.
Its core and exporter use the same encrypted Cloud SQL connector boundary as
Daytona, with a separate database, and all Harbor components use Harbor's
cluster-local authenticated Redis Service. A small idempotent bootstrap Job
creates the private `daytona` Harbor project before Daytona begins issuing
one-hour robot push credentials through `POST /api/v2.0/robots`.

This replaces the rejected two-registry design. Plain CNCF Distribution can
serve OCI v2 but cannot implement Harbor's robot endpoint; keeping it for only
the internal registry would add storage, auth, routing, and cleanup ownership
without enabling a capability Harbor does not already provide.

## Public routing

`gateway.yaml` binds the global external Application Load Balancer class to the
reserved global Premium IPv4 address `ambit-daytona-gateway-ip`
(observed as `136.69.63.102` on 2026-08-27) and Certificate Manager map
`ambit-daytona-public`. The named address resource, not the documentation
snapshot, is manifest authority. HTTP is restricted to the declared hostnames
and redirected to HTTPS with status 301. The HTTPS Routes preserve the original
Host header and WebSocket upgrades and provide these backends:

| Public endpoint | Kubernetes backend |
|---|---|
| `api.daytona.ambit.sh` | `daytona-system/daytona-api:3000` |
| `*.proxy.daytona.ambit.sh` and `proxy.daytona.ambit.sh` | `daytona-system/daytona-proxy:4000` |
| `minio.daytona.ambit.sh` | `daytona-state/minio:9000` |
| `registry.daytona.ambit.sh` | `daytona-state/daytona-harbor:80` |

The global GFE request/response timeout is set to its effective 86,400-second
maximum for all four backends. Active WebSockets also have a fixed 24-hour GFE
limit, so clients must retain reconnect/resume behavior rather than assuming an
unbounded TCP connection. Basic registry credentials never cross plaintext
transport.

The `daytona.ambit.sh` Cloud DNS zone must be delegated at the parent DNS
provider. Before exposing the Gateway, verify that API, proxy apex, wildcard
proxy, MinIO, and registry names all resolve publicly to the current value of
`ambit-daytona-gateway-ip` (currently `136.69.63.102`), and that every
certificate and certificate-map entry is `ACTIVE`. One-level
`*.daytona.ambit.sh` coverage includes the proxy apex but does not include
`*.proxy.daytona.ambit.sh`; the deep wildcard therefore requires its own
Certificate Manager coverage and DNS record. Conversely, the deep wildcard
does not cover the proxy apex. Both host patterns are mandatory.

GKE's managed Gateway supports `HTTPRoute`, not TCP routing. The
`daytona-ssh-gateway` Service therefore owns a separate regional external L4
frontend on reserved address resource `ambit-daytona-ssh`; it cannot share this
HTTP(S) Gateway. Verify `ssh.daytona.ambit.sh` resolves to that Service address
before exercising port 2222.

The MinIO peers and the namespace-identity-restricted API/runner clients use
HTTP inside the GKE VPC; public edge traffic uses the HTTPS Gateway endpoint.
If application-layer encryption between peers is required, add a private CA and
pod-DNS certificates as a routing/storage concern and distribute that CA to
every S3 client; do not disable certificate verification.

`daytona-state` is default-deny on ingress. Global external GKE Gateways use
zonal NEGs and reach Pods from the shared GFE and health-check ranges
`35.191.0.0/16` and `130.211.0.0/22`. Standard Kubernetes NetworkPolicy cannot
select one managed Gateway identity, so `state-network-policies.yaml` admits
only those two ranges to MinIO port 9000 and Harbor nginx port 8080. Host routing
and any future Cloud Armor policy remain the outer application boundary; broad
Internet-to-Pod ingress is not allowed.

The manifest render and client-side API decoding do not establish runtime
correctness. Before cutover, exercise Cloud SQL migration, Redis authentication
and restart recovery, MinIO STS policy scoping, volume backup/restore, registry
push/pull/delete, Harbor robot expiry, arbitrary preview ports/WebSockets, SSH,
secret rotation, and a real Ambit browser-to-agent journey.
