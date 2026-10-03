// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package controllers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	common_errors "github.com/daytonaio/common-go/pkg/errors"
	"github.com/daytonaio/runner/pkg/api/docs"
	"github.com/daytonaio/runner/pkg/common"
	"github.com/daytonaio/runner/pkg/generationstop"
	"github.com/daytonaio/runner/pkg/generationstopdocker"
	"github.com/daytonaio/runner/pkg/runner"
	"github.com/daytonaio/runner/pkg/storage"
	"github.com/daytonaio/runner/pkg/workingcopy"
	"github.com/docker/docker/client"
	"github.com/gin-gonic/gin"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// Opt-in composition gate: generated TypeScript clients and the actual API
// service call real Runner controllers, Docker generations and immutable S3.
// The command file is a JSON argv array; no shell or credentials enter it.
func TestWorkingCopyCaptureRealHTTPDockerMinIO(t *testing.T) {
	commandFile, image := os.Getenv("AMBIT_CAPTURE_HTTP_COMMAND_FILE"), os.Getenv("DAYTONA_WORKINGCOPY_DOCKER_TEST_IMAGE")
	if commandFile == "" || image == "" || os.Getenv("AMBIT_TEST_MINIO_ENDPOINT") == "" {
		t.Skip("requires task-owned Docker image, MinIO and a generated-client consumer command")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	for key, value := range map[string]string{
		"DAYTONA_API_URL": "http://127.0.0.1", "DAYTONA_RUNNER_TOKEN": "nosecret-local-test", "RUNNER_DOMAIN": "127.0.0.1",
		"AWS_ENDPOINT_URL": "http://" + os.Getenv("AMBIT_TEST_MINIO_ENDPOINT"), "AWS_ACCESS_KEY_ID": os.Getenv("AMBIT_TEST_MINIO_ACCESS_KEY"),
		"AWS_SECRET_ACCESS_KEY": os.Getenv("AMBIT_TEST_MINIO_SECRET_KEY"), "AWS_DEFAULT_BUCKET": os.Getenv("AMBIT_TEST_MINIO_BUCKET"), "AWS_REGION": "us-east-1",
	} {
		t.Setenv(key, value)
	}
	s3, err := minio.New(os.Getenv("AMBIT_TEST_MINIO_ENDPOINT"), &minio.Options{Creds: credentials.NewStaticV4(os.Getenv("AMBIT_TEST_MINIO_ACCESS_KEY"), os.Getenv("AMBIT_TEST_MINIO_SECRET_KEY"), ""), Region: "us-east-1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s3.MakeBucket(ctx, os.Getenv("AMBIT_TEST_MINIO_BUCKET"), minio.MakeBucketOptions{Region: "us-east-1"}); err != nil {
		t.Fatal(err)
	}
	objects, err := storage.GetPrivateObjectStorageClient()
	if err != nil {
		t.Fatal(err)
	}
	docker, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		t.Fatal(err)
	}
	defer docker.Close()
	name := fmt.Sprintf("capture-http-%d-%d", os.Getpid(), time.Now().UnixNano())
	owner := generationstop.Owner{TenantID: "11111111-1111-4111-8111-111111111111", UserID: "22222222-2222-4222-8222-222222222222", WorkspaceID: "33333333-3333-4333-8333-333333333333", RunID: "44444444-4444-4444-8444-444444444444", GrantID: "55555555-5555-4555-8555-555555555555", WorkingCopyID: "66666666-6666-4666-8666-666666666666"}
	fence := generationstop.Fence{WorkspaceExecutionManifestRef: "ambit.workspace-execution-manifest:v1:sha256:" + strings.Repeat("c", 64)}
	labels := map[string]string{"ambitTenantId": owner.TenantID, "ambitPrincipalId": owner.UserID, "ambitWorkspaceId": owner.WorkspaceID, "ambitTaskId": owner.RunID, "ambitGrantId": owner.GrantID, "ambitProfile": "managed-container", "ambitWorkspaceExecutionManifestRef": fence.WorkspaceExecutionManifestRef, "ambitRuntimeKind": "full_image_runtime_pack_provider_observation", "ambitRuntimeWorkspaceId": owner.WorkspaceID, "ambitRuntimeProductRunId": owner.RunID, "ambitRuntimeGrantId": owner.GrantID, "ambitRuntimeManifestRef": fence.WorkspaceExecutionManifestRef}
	args := []string{"run", "--pull=never", "--name", name, "--network", "none", "--user", "0", "--entrypoint", "sh"}
	for key, value := range labels {
		args = append(args, "--label", key+"="+value)
	}
	args = append(args, image, "-c", "mkdir -p /workspace/work && printf 'immutable HTTP custody' > /workspace/work/report.txt")
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if output, err := exec.CommandContext(cleanup, "docker", "rm", "-f", name).CombinedOutput(); err != nil {
			t.Errorf("task container cleanup: %s %v", output, err)
		}
	})
	if output, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput(); err != nil {
		t.Fatalf("task container: %s %v", output, err)
	}
	adapter, err := generationstopdocker.New(docker)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := adapter.InspectGeneration(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	stops, err := generationstop.NewService(adapter, objects)
	if err != nil {
		t.Fatal(err)
	}
	observer, err := generationstop.NewObserver(adapter)
	if err != nil {
		t.Fatal(err)
	}
	source := generationstop.Source{ProviderResourceID: name, ExpectedProfile: "managed-container", ExpectedRuntimeKind: "full_image_runtime_pack"}
	stopRequest := generationstop.StopRequest{OperationID: "77777777-7777-4777-8777-777777777777", Source: source, Owner: owner, Fence: fence, ExpectedGeneration: observed.Generation.ExpectedGeneration, Purpose: generationstop.Purpose{Kind: generationstop.PurposeWorkingCopyCapture}}
	stopRequest.RequestFingerprint, err = generationstop.ComputeRequestFingerprint(stopRequest)
	if err != nil {
		t.Fatal(err)
	}
	stopReceipt, err := stops.StopOnce(ctx, stopRequest)
	if err != nil {
		t.Fatal(err)
	}
	protocol, err := docs.CaptureProtocol()
	if err != nil {
		t.Fatal(err)
	}
	component, err := workingcopy.MeasureCaptureComponent(protocol)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := workingcopy.NewCaptureAuthority("ambit.core-document-lineage:v5:sha256:"+strings.Repeat("6", 64), component.Protocol.Digest, component.Helper.Digest)
	if err != nil {
		t.Fatal(err)
	}
	legacyAuthority, err := workingcopy.NewCaptureAuthority(authority.LineageRef, "sha256:"+strings.Repeat("7", 64), "sha256:"+strings.Repeat("8", 64))
	if err != nil {
		t.Fatal(err)
	}
	binding := workingcopy.CaptureBinding{ProviderName: "ambit-private-working-copy-capture", RequestFingerprint: strings.Repeat("a", 64), Authority: authority, Source: source, Owner: owner, StopAuthority: generationstop.StopAuthority{OperationID: stopRequest.OperationID, ReceiptRef: stopReceipt.ReceiptRef, ReceiptDigest: stopReceipt.ReceiptDigest, TerminalGeneration: stopReceipt.TerminalGeneration, Fence: fence}, Selector: workingcopy.CaptureSelector{SemanticZoneRef: "ambit.workspace-zone/work@1", ZoneRelativePath: "report.txt"}}
	service, err := workingcopy.NewService(docker, objects, stops, component, observer)
	if err != nil {
		t.Fatal(err)
	}
	_, err = runner.GetInstance(&runner.RunnerInstanceConfig{WorkingCopyCaptures: service})
	if err != nil {
		t.Fatal(err)
	}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(common_errors.NewErrorMiddleware(common.HandlePossibleDockerError, false))
	router.POST("/sandboxes/:sandboxId/working-copy-captures/capabilities", WorkingCopyCaptureCapabilities)
	router.POST("/sandboxes/:sandboxId/working-copy-captures", CaptureWorkingCopy)
	router.POST("/sandboxes/:sandboxId/working-copy-captures/read", ReadWorkingCopyCapture)
	router.POST("/sandboxes/:sandboxId/working-copy-captures/observe", ObserveWorkingCopyCapture)
	server := httptest.NewServer(router)
	defer server.Close()
	fixture := filepath.Join(t.TempDir(), "fixture.json")
	data, _ := json.Marshal(map[string]any{"url": server.URL, "sandbox": map[string]any{"id": name, "organizationId": "daytona-org-1", "runnerId": "runner-1", "labels": labels}, "request": workingcopy.CaptureCapabilitiesRequest{Source: source, Owner: owner, Fence: fence, Authority: authority}, "binding": binding, "component": component, "legacy": true, "staleAuthority": legacyAuthority})
	if err := os.WriteFile(fixture, data, 0600); err != nil {
		t.Fatal(err)
	}
	commandBytes, err := os.ReadFile(commandFile)
	if err != nil {
		t.Fatal(err)
	}
	var command []string
	if err := json.Unmarshal(commandBytes, &command); err != nil || len(command) == 0 {
		t.Fatalf("invalid consumer argv: %v", err)
	}
	consumer := exec.CommandContext(ctx, command[0], command[1:]...)
	consumer.Env = append(os.Environ(), "AMBIT_CAPTURE_HTTP_FIXTURE="+fixture)
	consumer.Stdout, consumer.Stderr = os.Stdout, os.Stderr
	if err := consumer.Run(); err != nil {
		t.Fatal(err)
	}
	t.Log("API1 accepts exact R0 legacy authority through real HTTP/Docker/MinIO")
}
