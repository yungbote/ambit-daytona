# C18 live MinIO integration collector

This command exercises the Runner's production private-object storage adapter,
not a parallel S3 client. It requires the same live environment used by the
Runner:

```text
AWS_ENDPOINT_URL
AWS_ACCESS_KEY_ID
AWS_SECRET_ACCESS_KEY
AWS_DEFAULT_BUCKET
AWS_REGION
```

The canonical `C18MinioIntegrationRun@1` request contains only the exact
Daytona source revision, tree, source-set digest, and one new canonical run
UUID. Credentials, endpoint, bucket, and object keys never enter the receipt.

Run it from the exact admitted source checkout:

```sh
go run ./apps/runner/cmd/c18-minio-integration \
  --request /absolute/private/c18-minio-integration-run.json \
  --output /absolute/private/c18-minio-integration-receipt.json
```

The command operates only below a run-UUID-owned private prefix. It proves the
exact seven-operation roster:

1. conditional create, including sixteen concurrent contenders and exactly one
   winner;
2. immutable write-conflict rejection through the production precondition
   error class;
3. provider checksum and metadata stat;
4. bounded range read;
5. streaming create/open with exact length, bytes, and metadata;
6. bounded, sorted listing; and
7. deletion followed by not-found proof for all three task-owned objects.

Best-effort cleanup is retained for failure paths; success requires exact
deletion before publication. The output path must not exist. The command
atomically commits one mode-`0600`, canonical, self-digested
`C18MinioIntegrationReceipt@1` file and records concrete counts and digests
without exposing storage authority values.

The checked-in consumer fixture is
`apps/runner/pkg/c18providerintegration/testdata/c18-minio-integration-receipt.golden.json`.
