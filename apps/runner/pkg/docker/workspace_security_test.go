package docker

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daytonaio/runner/pkg/sandboxsecurity"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)

func securityFixture(t *testing.T) (*DockerClient, *container.InspectResponse) {
	t.Helper()
	d := &DockerClient{workspaceSecurityProfile: workspaceSecurityRestricted}
	config := &container.Config{User: "daytona", Env: []string{"EXAMPLE=value"}}
	host := &container.HostConfig{NetworkMode: "bridge", Binds: []string{"/owned:/workspace"},
		Resources: container.Resources{Memory: 2147483648, CPUPeriod: 100000, CPUQuota: 200000}}
	if err := d.applyWorkspaceSecurityProfile(config, host); err != nil {
		t.Fatal(err)
	}
	return d, &container.InspectResponse{ContainerJSONBase: &container.ContainerJSONBase{ID: "workspace", HostConfig: host, State: &container.State{}}, Config: config}
}

func TestWorkspaceSecurityDefaultLeavesLegacyBehaviorUnchanged(t *testing.T) {
	for _, profile := range []string{"", workspaceSecurityLegacy} {
		d := &DockerClient{workspaceSecurityProfile: profile}
		config := &container.Config{User: "custom-user"}
		host := &container.HostConfig{Privileged: true, CapAdd: []string{"ALL"}, SecurityOpt: []string{"seccomp=unconfined"}}
		before, _ := json.Marshal([]any{config, host})
		if err := d.applyWorkspaceSecurityProfile(config, host); err != nil {
			t.Fatal(err)
		}
		after, _ := json.Marshal([]any{config, host})
		if string(before) != string(after) {
			t.Fatal("legacy configuration changed")
		}
	}
	if _, err := NewDockerClient(context.Background(), DockerClientConfig{WorkspaceSecurityProfile: "unrecognized"}); err == nil {
		t.Fatal("invalid policy reached Docker construction")
	}
}

func TestRestrictedProfilePreservesOrdinaryRuntimeContracts(t *testing.T) {
	d, info := securityFixture(t)
	if err := d.validateWorkspaceSecurityConfiguration(info); err != nil {
		t.Fatal(err)
	}
	if info.Config.User != "daytona" || info.HostConfig.NetworkMode != "bridge" || info.HostConfig.ReadonlyRootfs ||
		info.HostConfig.Memory != 2147483648 || info.HostConfig.CPUQuota != 200000 ||
		!reflect.DeepEqual(info.HostConfig.Binds, []string{"/owned:/workspace"}) {
		t.Fatal("ordinary identity, writable filesystem, resources or network were changed")
	}
	// Runtime conversion cannot restore its former unconfined overrides.
	info.HostConfig.Runtime = "kata-clh"
	info.HostConfig.CapAdd = []string{"ALL"}
	info.HostConfig.SecurityOpt = []string{"seccomp=unconfined", "apparmor=unconfined"}
	if err := d.applyWorkspaceSecurityProfile(info.Config, info.HostConfig); err != nil {
		t.Fatal(err)
	}
	if info.HostConfig.Runtime != "kata-clh" || d.validateWorkspaceSecurityConfiguration(info) != nil {
		t.Fatal("runtime selection or restricted configuration did not survive conversion")
	}
}

func TestRestrictedConfigurationRejectsEveryUnsafeOverride(t *testing.T) {
	for name, mutate := range map[string]func(*container.HostConfig){
		"privileged":   func(h *container.HostConfig) { h.Privileged = true },
		"cap-add":      func(h *container.HostConfig) { h.CapAdd = []string{"SYS_ADMIN"} },
		"cap-drop":     func(h *container.HostConfig) { h.CapDrop = nil },
		"host-network": func(h *container.HostConfig) { h.NetworkMode = "host" },
		"host-pid":     func(h *container.HostConfig) { h.PidMode = "host" },
		"host-ipc":     func(h *container.HostConfig) { h.IpcMode = "host" },
		"host-cgroup":  func(h *container.HostConfig) { h.CgroupnsMode = "host" },
		"no-nnp": func(h *container.HostConfig) {
			h.SecurityOpt = []string{"seccomp=" + sandboxsecurity.RootlessSeccomp()}
		},
		"different-seccomp": func(h *container.HostConfig) { h.SecurityOpt[1] = "seccomp=unconfined" },
		"extra-override":    func(h *container.HostConfig) { h.SecurityOpt = append(h.SecurityOpt, "apparmor=unconfined") },
	} {
		t.Run(name, func(t *testing.T) {
			d, info := securityFixture(t)
			mutate(info.HostConfig)
			if d.validateWorkspaceSecurityConfiguration(info) == nil {
				t.Fatal("unsafe configuration passed despite a claimed restricted label")
			}
		})
	}
}

func TestRestrictedStartDoesNotStartOrConvertAnIncompatibleWorkspace(t *testing.T) {
	_, info := securityFixture(t)
	info.HostConfig.Privileged = true
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodGet || !strings.HasSuffix(r.URL.Path, "/containers/workspace/json") {
			t.Errorf("unexpected mutation: %s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected mutation", 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(info)
	}))
	defer server.Close()
	api, err := client.NewClientWithOpts(client.WithHost(server.URL), client.WithVersion("1.51"), client.WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close()
	d := &DockerClient{apiClient: api, workspaceSecurityProfile: workspaceSecurityRestricted}
	if _, _, err := d.Start(context.Background(), "workspace", nil, nil, map[string]string{"forceKata": "true"}); err == nil {
		t.Fatal("incompatible existing workspace was admitted")
	}
	if requests.Load() != 1 {
		t.Fatalf("unexpected request count: %d", requests.Load())
	}
}

func TestRestrictedKernelSecurityRejectsLatentCapabilities(t *testing.T) {
	zero := "0000000000000000"
	good := sandboxsecurity.ProcessSecurity{NoNewPrivileges: true, SeccompMode: 2, EffectiveCapabilities: zero, PermittedCapabilities: zero, BoundingCapabilities: zero, InheritableCapabilities: zero, AmbientCapabilities: zero}
	if err := validateRestrictedProcessSecurity(good); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*sandboxsecurity.ProcessSecurity){
		func(p *sandboxsecurity.ProcessSecurity) { p.NoNewPrivileges = false },
		func(p *sandboxsecurity.ProcessSecurity) { p.SeccompMode = 0 },
		func(p *sandboxsecurity.ProcessSecurity) { p.EffectiveCapabilities = "0000000000000001" },
		func(p *sandboxsecurity.ProcessSecurity) { p.PermittedCapabilities = "0000000000000001" },
		func(p *sandboxsecurity.ProcessSecurity) { p.BoundingCapabilities = "0000000000000001" },
		func(p *sandboxsecurity.ProcessSecurity) { p.InheritableCapabilities = "0000000000000001" },
		func(p *sandboxsecurity.ProcessSecurity) { p.AmbientCapabilities = "0000000000000001" },
	} {
		bad := good
		mutate(&bad)
		if validateRestrictedProcessSecurity(bad) == nil {
			t.Fatal("unsafe kernel state passed")
		}
	}
}

func TestRestrictedWorkspaceAgainstRealDocker(t *testing.T) {
	image := os.Getenv("AMBIT_WORKSPACE_SECURITY_DOCKER_TEST_IMAGE")
	if image == "" {
		t.Skip("explicit local qualification image required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	api, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close()
	d := &DockerClient{apiClient: api, workspaceSecurityProfile: workspaceSecurityRestricted}
	config := &container.Config{Image: image, User: "1000:1000", Entrypoint: []string{"sleep"}, Cmd: []string{"30"}}
	host := &container.HostConfig{NetworkMode: "none"}
	if err := d.applyWorkspaceSecurityProfile(config, host); err != nil {
		t.Fatal(err)
	}
	created, err := api.ContainerCreate(ctx, config, host, nil, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := api.ContainerRemove(cleanupCtx, created.ID, container.RemoveOptions{Force: true}); err != nil {
			t.Errorf("remove owned qualification container: %v", err)
		}
	}()
	if err := api.ContainerStart(ctx, created.ID, container.StartOptions{}); err != nil {
		t.Fatal(err)
	}
	info, err := d.ContainerInspect(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.admitRunningWorkspaceSecurity(ctx, info); err != nil {
		t.Fatal(err)
	}
	observed, err := sandboxsecurity.ObserveProcess(info.State.Pid)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("image=%s actualUser=%s runtime=%s privileged=%t ipc=%s cgroup=%s processSecurity=%+v",
		info.Image, info.Config.User, info.HostConfig.Runtime, info.HostConfig.Privileged,
		info.HostConfig.IpcMode, info.HostConfig.CgroupnsMode, observed)
}

func TestRejectedNewWorkspaceCleanupPreservesOtherCreators(t *testing.T) {
	for _, test := range []struct {
		name           string
		createdHere    bool
		cancelled      bool
		cleanupFailure bool
	}{
		{name: "new container", createdHere: true},
		{name: "adopted conflict"},
		{name: "cancelled attempt", createdHere: true, cancelled: true},
		{name: "visible cleanup failure", createdHere: true, cleanupFailure: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, info := securityFixture(t)
			info.HostConfig.Privileged = true
			var deletes atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch {
				case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/containers/exact-created-id/json"):
					_ = json.NewEncoder(w).Encode(info)
				case r.Method == http.MethodDelete && strings.HasSuffix(r.URL.Path, "/containers/exact-created-id"):
					deletes.Add(1)
					if test.cleanupFailure {
						w.WriteHeader(http.StatusInternalServerError)
						_, _ = w.Write([]byte(`{"message":"fixture removal failed"}`))
					} else {
						w.WriteHeader(http.StatusNoContent)
					}
				default:
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
					w.WriteHeader(http.StatusInternalServerError)
				}
			}))
			defer server.Close()
			api, err := client.NewClientWithOpts(client.WithHost(server.URL), client.WithVersion("1.51"), client.WithHTTPClient(server.Client()))
			if err != nil {
				t.Fatal(err)
			}
			defer api.Close()
			d := &DockerClient{apiClient: api, workspaceSecurityProfile: workspaceSecurityRestricted}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if test.cancelled {
				cancel()
			}
			err = d.validateCreatedWorkspaceSecurity(ctx, "exact-created-id", test.createdHere)
			if err == nil || (test.cleanupFailure && !strings.Contains(err.Error(), "remains pending cleanup")) {
				t.Fatalf("rejection or cleanup failure lost: %v", err)
			}
			want := int32(0)
			if test.createdHere {
				want = 1
			}
			if deletes.Load() != want {
				t.Fatalf("cleanup count %d, want %d", deletes.Load(), want)
			}
		})
	}
}

func TestRejectedRecreationRetainsAndRestoresOriginal(t *testing.T) {
	_, original := securityFixture(t)
	original.ID = "original-id"
	original.HostConfig.Runtime = "runc"
	_, rejected := securityFixture(t)
	rejected.ID = "replacement-id"
	rejected.HostConfig.Privileged = true
	requests := make(chan string, 16)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/v1.51")
		requests <- r.Method + " " + path
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + path {
		case "GET /containers/workspace/json":
			_ = json.NewEncoder(w).Encode(original)
		case "POST /commit":
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"Id":"image-id"}`))
		case "POST /containers/workspace/rename":
			if !strings.HasPrefix(r.URL.Query().Get("name"), "workspace-old-") {
				t.Error("original was not renamed for recovery")
			}
			w.WriteHeader(http.StatusNoContent)
		case "POST /containers/create":
			var body struct {
				container.Config
				HostConfig *container.HostConfig
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.HostConfig == nil || body.HostConfig.Privileged {
				t.Errorf("restricted settings were lost during recreation: %v", err)
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"Id":"replacement-id","Warnings":[]}`))
		case "GET /containers/replacement-id/json":
			_ = json.NewEncoder(w).Encode(rejected)
		case "DELETE /containers/replacement-id":
			w.WriteHeader(http.StatusNoContent)
		case "POST /containers/original-id/rename":
			if r.URL.Query().Get("name") != "workspace" {
				t.Error("original name was not restored")
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected mutation/request: %s %s", r.Method, path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer server.Close()
	api, err := client.NewClientWithOpts(client.WithHost(server.URL), client.WithVersion("1.51"), client.WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close()
	d := &DockerClient{apiClient: api, workspaceSecurityProfile: workspaceSecurityRestricted, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	_, err = d.recreateContainerUnderSameID(context.Background(), "workspace", "fixture", original, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "does not satisfy restricted-v1") {
		t.Fatalf("rejected replacement was accepted: %v", err)
	}
	want := []string{"GET /containers/workspace/json", "POST /commit", "POST /containers/workspace/rename", "POST /containers/create", "GET /containers/replacement-id/json", "DELETE /containers/replacement-id", "POST /containers/original-id/rename"}
	got := make([]string, 0, len(want))
	for len(requests) > 0 {
		got = append(got, <-requests)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("rollback order differs: got %v, want %v", got, want)
	}
}
