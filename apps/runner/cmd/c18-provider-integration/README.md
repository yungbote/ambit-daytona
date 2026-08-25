# C18 live provider integration collector

This command collects the release-time provider evidence that cannot exist
before the final Runner policy, images, Daytona API, Runner, MinIO custody, and
one authority-labelled parent sandbox are live. It never creates a policy,
changes Runner configuration, deploys a workload, or manufactures a receipt.

The input is one canonical `C18ProviderLiveRun@1` JSON file. It contains:

- the exact Daytona source revision, tree, and source-set digest;
- a mode-regular, absolute Runner policy path with exact byte length and SHA-256;
- the parent sandbox source, five-dimensional provider owner, and execution
  manifest fence already present in that sandbox's immutable labels;
- exactly twelve rows sorted by `facet`, then `mode`: `cancel` and `success`
  for each of `data_analysis`, `pdf`, `presentation`, `research`,
  `spreadsheet`, and `web_application`;
- a unique canonical operation UUID and artifact-render-job UUID for every row;
- absolute, regular, no-follow request/source files with exact positive byte
  lengths and SHA-256 digests; and
- bounded execution, observation, polling, and post-claim cancellation timing.

The request files must be canonical C18 command-v2 JSON. The source files are
the exact request-bound artifact bytes. The command freshly observes the
parent generation before every execution and fails unless it is running and
matches the configured source, owner, and fence.

Authentication is supplied only through the existing Daytona host variables:

```text
DAYTONA_API_URL
DAYTONA_API_KEY
DAYTONA_JWT_TOKEN
DAYTONA_ORGANIZATION_ID
```

JWT use requires `DAYTONA_ORGANIZATION_ID`. When both credential variables are
present, `DAYTONA_API_KEY` has the same precedence as the backend Daytona host
adapter. Credential and endpoint values never enter the output.

Run it from the exact admitted source checkout:

```sh
go run ./apps/runner/cmd/c18-provider-integration \
  --request /absolute/private/c18-provider-live-run.json \
  --output /absolute/private/c18-provider-live-collection.json
```

The output path must not exist. The command commits one mode-`0600`, canonical,
self-digested `C18ProviderLiveCollection@1` file atomically. It contains:

- the complete canonical Runner policy and its SHA-256;
- twelve unique, fully validated provider receipts, bound to the correct
  facet-to-pack policy;
- six successful authenticated HTTP streams with exact request-wire,
  response-wire, operation, status, and receipt digests; and
- the measured collection interval.

Cancellation is not inferred from a disconnected socket. For each cancellation
row the collector waits until the durable operation claim is observable as
`partial`, aborts that authenticated request, then independently polls the
observe endpoint until the provider publishes an exact `cancelled/130` receipt
with zero output bytes and proven child-container absence. A raced success,
missing terminal receipt, retained output, or unresolved operation fails the
whole collection.

The checked-in full-schema consumer fixture is
`apps/runner/pkg/c18providerintegration/testdata/c18-provider-live-collection.golden.json`.
