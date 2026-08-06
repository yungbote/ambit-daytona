// Package jail provides jailed command execution under an eBPF egress firewall.
//
// A jailed command can only make network connections to explicitly allowed domains.
// DNS responses are monitored via eBPF to learn allowed IPs dynamically. All other
// egress traffic is blocked at the kernel level.
//
// Optionally, secrets can be injected into outbound HTTPS requests via a MITM proxy,
// so child processes never see real secret values in their environment.
//
// Requires root or CAP_BPF. Linux only (cgroup v2 + eBPF).
//
// Basic usage:
//
//	exitCode, err := jail.Exec(ctx, jail.Config{
//	    Domains: []string{"api.example.com"},
//	}, []string{"curl", "https://api.example.com"})
package jail

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/daytonaio/daytona/libs/netleash/pkg/firewall"
	"github.com/daytonaio/daytona/libs/netleash/pkg/proxy"
)

// Secret defines a secret to inject into outbound HTTPS requests via the MITM proxy.
// The child process sees a placeholder value in its environment; the proxy replaces
// it with the real Value on the wire, scoped to the listed Hosts.
type Secret struct {
	Name  string   // environment variable name (e.g., "OPENAI_API_KEY")
	Value string   // real secret value (never exposed to the child process)
	Hosts []string // inject only for requests to these hosts
}

// Config controls how a jailed command executes.
type Config struct {
	// Domains is the list of allowed egress domains. Required (at least one).
	// Entries prefixed with "*." enable wildcard suffix matching.
	Domains []string

	// AllowedExecs is the list of allowed executable paths. Optional.
	// When non-empty, LSM BPF exec filtering is enabled — only listed binaries
	// can be executed inside the jail. Requires CONFIG_BPF_LSM=y.
	AllowedExecs []string

	// User drops privileges to this user before running the child process.
	// Accepts username or numeric UID. Optional — if empty, child runs as current user.
	User string

	// Secrets configures MITM proxy-based secret injection. Optional.
	// When non-empty, an ephemeral CA and MITM proxy are started automatically.
	Secrets []Secret

	// EnforceProxy hardens the domain allow list: the MITM proxy is started even
	// without secrets, and the eBPF filter gates the standard web ports (TCP
	// 80/443, UDP 443) so the child's HTTP(S) traffic can only go through the
	// proxy — which enforces the allow list on the requested hostname (SNI/Host)
	// instead of on DNS-learned IPs, closing the shared-IP / domain-fronting
	// bypass. Non-web protocols keep the IP-allowlist behavior. Optional.
	EnforceProxy bool

	// Stdout and Stderr control where the child process writes its output.
	// If nil, they default to os.Stdout and os.Stderr respectively.
	Stdout io.Writer
	Stderr io.Writer

	// Stdin controls the child process's stdin. If nil, defaults to os.Stdin.
	Stdin io.Reader

	// Env sets additional environment variables for the child process.
	// These are appended to os.Environ(). The library also injects proxy/secret
	// env vars automatically; caller-supplied entries take lower precedence.
	Env []string

	// ProxyToken, if set, requires clients to authenticate with
	// Proxy-Authorization: Bearer <token>. Optional.
	ProxyToken string

	// OnBlocked is called for each blocked egress packet. Optional.
	// If nil, blocked packets are logged via slog.Warn.
	OnBlocked func(dstIP string, dstPort uint16, proto string)

	// OnExecBlocked is called for each blocked exec attempt. Optional.
	// If nil, blocked execs are logged via slog.Warn. Only active when AllowedExecs is set.
	OnExecBlocked func(path string)

	// Logger sets the logger for the jail and its sub-components (firewall, proxy).
	// If nil, slog.Default() is used.
	Logger *slog.Logger
}

// Jail represents an active eBPF network jail.
// Use New + Setup + Run + Close for fine-grained control,
// or use the top-level Exec function for simple cases.
type Jail struct {
	cfg         Config
	log         *slog.Logger
	fw          *firewall.Firewall
	proxyServer *proxy.Server
	tempFiles   []string
}

// Exec runs a command inside an eBPF-enforced network jail.
// It is the one-call equivalent of:
//
//	netleash --allow domain1 --allow domain2 -- cmd args...
//
// It blocks until the command exits and returns its exit code.
// All resources (cgroup, eBPF programs, optional proxy) are cleaned up before return.
// Requires root or CAP_BPF.
func Exec(ctx context.Context, cfg Config, args []string) (int, error) {
	j, err := New(cfg)
	if err != nil {
		return 1, err
	}
	defer j.Close()

	if err := j.Setup(); err != nil {
		return 1, err
	}

	return j.Run(ctx, args)
}

// New creates a Jail with the given configuration. Does not allocate resources yet.
func New(cfg Config) (*Jail, error) {
	if len(cfg.Domains) == 0 {
		return nil, fmt.Errorf("jail: at least one allowed domain is required")
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	return &Jail{cfg: cfg, log: log}, nil
}

// Setup creates the cgroup, loads eBPF programs, and optionally starts the MITM proxy.
// Must be called before Run.
func (j *Jail) Setup() error {
	// Merge secret hosts into the domain allow list.
	allDomains := make(map[string]bool)
	for _, d := range j.cfg.Domains {
		allDomains[d] = true
	}
	for _, s := range j.cfg.Secrets {
		for _, h := range s.Hosts {
			if !allDomains[h] {
				allDomains[h] = true
				j.log.Debug("auto-added secret host to allow list", "host", h)
			}
		}
	}
	domainList := make([]string, 0, len(allDomains))
	for d := range allDomains {
		domainList = append(domainList, d)
	}

	fwCfg := firewall.Config{
		Domains:       domainList,
		AllowedExecs:  j.cfg.AllowedExecs,
		User:          j.cfg.User,
		Stdout:        j.cfg.Stdout,
		Stderr:        j.cfg.Stderr,
		Stdin:         j.cfg.Stdin,
		Env:           j.cfg.Env,
		OnBlocked:     j.cfg.OnBlocked,
		OnExecBlocked: j.cfg.OnExecBlocked,
		Logger:        j.log,
	}

	// Start the MITM proxy when secrets are configured or when the allow list is
	// proxy-enforced (the proxy is then the mandatory path for web traffic).
	if len(j.cfg.Secrets) > 0 || j.cfg.EnforceProxy {
		if err := j.setupProxy(&fwCfg, domainList); err != nil {
			return err
		}
	}

	j.fw = firewall.New(fwCfg)
	if err := j.fw.Setup(); err != nil {
		return fmt.Errorf("jail: firewall setup: %w", err)
	}

	return nil
}

// setupProxy starts the MITM proxy with ephemeral CA and configures the firewall accordingly.
func (j *Jail) setupProxy(fwCfg *firewall.Config, domainList []string) error {
	ca, err := proxy.GenerateCA()
	if err != nil {
		return fmt.Errorf("jail: generating CA: %w", err)
	}

	// Write combined CA cert file (system CAs + our ephemeral CA).
	caCertFile, err := proxy.WriteCombinedCACert(ca.PEM)
	if err != nil {
		return fmt.Errorf("jail: writing CA cert: %w", err)
	}
	j.tempFiles = append(j.tempFiles, caCertFile)

	// Write raw CA cert separately (keytool needs a single cert, not a bundle).
	rawCAFile, err := os.CreateTemp("", "netleash-ca-raw-*.pem")
	if err != nil {
		return fmt.Errorf("jail: writing raw CA cert: %w", err)
	}
	rawCAFile.Write(ca.PEM)
	rawCAFile.Close()
	j.tempFiles = append(j.tempFiles, rawCAFile.Name())

	// Build proxy secret configs with generated placeholders.
	secretConfigs := make([]proxy.SecretConfig, len(j.cfg.Secrets))
	fwCfg.SecretsEnv = make(map[string]string)
	for i, s := range j.cfg.Secrets {
		placeholder := proxy.GeneratePlaceholder()
		secretConfigs[i] = proxy.SecretConfig{
			Name:        s.Name,
			Placeholder: placeholder,
			Value:       s.Value,
			Hosts:       s.Hosts,
		}
		fwCfg.SecretsEnv[s.Name] = placeholder
	}

	injector := proxy.NewInjector(secretConfigs)

	opts := []proxy.Option{proxy.WithLogger(j.log)}
	if j.cfg.ProxyToken != "" {
		opts = append(opts, proxy.WithAuthToken(j.cfg.ProxyToken))
	}
	j.proxyServer = proxy.NewServer("127.0.0.1:0", ca, injector, domainList, "", opts...)
	proxyAddr, err := j.proxyServer.Start()
	if err != nil {
		return fmt.Errorf("jail: starting proxy: %w", err)
	}

	fwCfg.ProxyAddr = proxyAddr
	fwCfg.CACertFile = caCertFile
	fwCfg.EnforceProxy = j.cfg.EnforceProxy

	// Create a Java truststore (system CAs + our CA) for JVM applications.
	if javaTrustStore := proxy.CreateJavaTrustStore(rawCAFile.Name()); javaTrustStore != "" {
		fwCfg.JavaTrustStore = javaTrustStore
		j.tempFiles = append(j.tempFiles, javaTrustStore)
		j.log.Debug("JVM truststore created", "path", javaTrustStore)
	}

	j.log.Info("MITM proxy active", "addr", proxyAddr, "secrets", len(j.cfg.Secrets))
	return nil
}

// Run starts the command inside the jail and blocks until it exits.
// Returns the child's exit code.
func (j *Jail) Run(ctx context.Context, args []string) (int, error) {
	if len(args) == 0 {
		return 1, fmt.Errorf("jail: at least one argument (the command) is required")
	}
	if j.fw == nil {
		return 1, fmt.Errorf("jail: Setup must be called before Run")
	}
	return j.fw.RunProcess(ctx, args)
}

// Close tears down all resources: eBPF programs, cgroup, proxy, temp files.
// Safe to call multiple times.
func (j *Jail) Close() {
	if j.fw != nil {
		j.fw.Cleanup()
		j.fw = nil
	}
	if j.proxyServer != nil {
		j.proxyServer.Close()
		j.proxyServer = nil
	}
	for _, f := range j.tempFiles {
		os.Remove(f)
	}
	j.tempFiles = nil
}
