package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/daytonaio/daytona/libs/netleash/internal/container"
	"github.com/daytonaio/daytona/libs/netleash/pkg/firewall"
	"github.com/daytonaio/daytona/libs/netleash/pkg/jail"
	"github.com/daytonaio/daytona/libs/netleash/pkg/proxy"
	"github.com/daytonaio/daytona/libs/netleash/pkg/runtime"
)

// stringList implements flag.Value for repeatable flags.
type stringList []string

func (s *stringList) String() string { return fmt.Sprintf("%v", *s) }
func (s *stringList) Set(val string) error {
	for _, v := range strings.Split(val, ",") {
		v = strings.TrimSpace(v)
		if v != "" {
			*s = append(*s, v)
		}
	}
	return nil
}

func main() {
	var domains stringList
	var secretSpecs stringList
	var allowedExecs stringList
	var verbose bool
	var cgroupPath string
	var containerID string
	var interfaceName string
	var tapMode bool
	var secretFile string
	var proxyToken string
	var enforceProxy bool
	var serverMode bool
	var listenAddr string
	var dnsServer string
	var runAsUser string

	flag.Var(&domains, "allow", "Domain to whitelist (can be repeated, comma-separated)")
	flag.Var(&allowedExecs, "allow-exec", "Executable path to whitelist (can be repeated; requires LSM BPF)")
	flag.Var(&secretSpecs, "secret", "Secret in NAME=VALUE:host1,host2 format (can be repeated)")
	flag.StringVar(&secretFile, "secret-file", "", "Read secrets from file (one NAME=VALUE:host1,host2 per line; use - for stdin)")
	flag.StringVar(&proxyToken, "proxy-token", "", "Require Bearer token for proxy authentication")
	flag.BoolVar(&enforceProxy, "enforce-proxy", false, "Force HTTP(S) through the MITM proxy: web ports (TCP 80/443, UDP 443) are blocked in eBPF except to the proxy, which enforces the allow list by hostname (starts the proxy even without secrets)")
	flag.BoolVar(&serverMode, "server", false, "Run as standalone proxy server (no eBPF, no root required)")
	flag.StringVar(&listenAddr, "listen", "127.0.0.1:8080", "Proxy listen address (server mode)")
	flag.BoolVar(&verbose, "v", false, "Verbose output")
	flag.StringVar(&cgroupPath, "cgroup", "", "Attach to existing cgroup path (attach mode)")
	flag.StringVar(&containerID, "container", "", "Attach to Docker container by ID or name (attach mode)")
	flag.StringVar(&interfaceName, "interface", "", "Attach TC eBPF to network interface (e.g., tap0, veth0)")
	flag.BoolVar(&tapMode, "tap", false, "Swap TC attach directions for tap devices (use with --interface)")
	flag.StringVar(&dnsServer, "dns", "", "DNS server address for name resolution (e.g., 8.8.8.8; useful in netns where system DNS is unreachable)")
	flag.StringVar(&runAsUser, "user", "", "Run jailed process as this user (name or UID; drops privileges after eBPF setup)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  %s [options] -- <command> [args...]     (process wrapper mode)\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s [options] --cgroup <path>            (attach to cgroup)\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s [options] --container <id>           (attach to Docker container)\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s [options] --interface <name>         (attach to network interface)\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s [options] --server                   (standalone proxy mode)\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Kernel-level network containment with secret injection.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  sudo %s --allow example.com -- curl https://example.com\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  sudo %s --allow github.com --container my-container\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  sudo %s --allow api.openai.com --secret OPENAI_API_KEY=sk-xxx:api.openai.com -- python app.py\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  sudo %s --allow api.openai.com --secret-file /etc/netleash/secrets.conf -- python app.py\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s --server --listen 0.0.0.0:8080 --allow api.openai.com --secret-file secrets.conf\n", os.Args[0])
	}
	flag.Parse()

	cmdArgs := flag.Args()
	attachMode := cgroupPath != "" || containerID != "" || interfaceName != ""

	// Configure slog level based on -v flag (do this early so validation errors log correctly).
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: level,
	})))

	// Override the system DNS resolver if --dns is set (needed in netns where
	// the host's systemd-resolved on 127.0.0.53 is unreachable).
	if dnsServer != "" {
		if !strings.Contains(dnsServer, ":") {
			dnsServer = dnsServer + ":53"
		}
		net.DefaultResolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{}
				return d.DialContext(ctx, "udp", dnsServer)
			},
		}
		slog.Debug("using custom DNS resolver", "server", dnsServer)
	}

	// Validate flag combinations.
	if cgroupPath != "" && containerID != "" {
		slog.Error("--cgroup and --container are mutually exclusive")
		os.Exit(1)
	}
	if interfaceName != "" && (cgroupPath != "" || containerID != "") {
		slog.Error("--interface cannot be combined with --cgroup or --container")
		os.Exit(1)
	}
	if tapMode && interfaceName == "" {
		slog.Error("--tap requires --interface")
		os.Exit(1)
	}
	if len(allowedExecs) > 0 && interfaceName != "" {
		slog.Error("--allow-exec cannot be used with --interface (LSM exec filtering requires cgroup mode)")
		os.Exit(1)
	}
	if serverMode && (attachMode || len(cmdArgs) > 0) {
		slog.Error("--server cannot be combined with --cgroup, --container, or a command")
		os.Exit(1)
	}
	if enforceProxy && serverMode {
		slog.Error("--enforce-proxy requires eBPF (process wrapper or attach mode); in --server mode the proxy already enforces the allow list for clients that use it")
		os.Exit(1)
	}
	if attachMode && len(cmdArgs) > 0 {
		slog.Error("cannot specify a command in attach mode (--cgroup/--container)")
		os.Exit(1)
	}
	if !serverMode && !attachMode && len(cmdArgs) == 0 {
		flag.Usage()
		os.Exit(1)
	}
	if len(domains) == 0 {
		slog.Error("at least one --allow domain is required")
		os.Exit(1)
	}

	// Server mode: standalone proxy, no eBPF, no root.
	if serverMode {
		runServerMode(domains, secretSpecs, secretFile, proxyToken, listenAddr)
		return
	}

	if os.Geteuid() != 0 {
		slog.Error("must run as root (need CAP_BPF + cgroup access)")
		os.Exit(1)
	}

	// Process wrapper mode: delegate to pkg/jail.
	if !attachMode {
		secrets, err := parseSecretFlags(secretSpecs)
		if err != nil {
			slog.Error("invalid --secret flag", "error", err)
			os.Exit(1)
		}
		if secretFile != "" {
			fileSecrets, err := parseSecretFileAsJailSecrets(secretFile)
			if err != nil {
				slog.Error("invalid --secret-file", "error", err)
				os.Exit(1)
			}
			secrets = append(secrets, fileSecrets...)
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			<-sigCh
			cancel()
		}()

		exitCode, err := jail.Exec(ctx, jail.Config{
			Domains:      []string(domains),
			AllowedExecs: []string(allowedExecs),
			User:         runAsUser,
			Secrets:      secrets,
			ProxyToken:   proxyToken,
			EnforceProxy: enforceProxy,
		}, cmdArgs)
		if err != nil {
			slog.Error("execution failed", "error", err)
			os.Exit(1)
		}
		os.Exit(exitCode)
	}

	// Attach mode: container/cgroup/interface (uses internal packages directly).
	runAttachMode(domains, allowedExecs, secretSpecs, secretFile, proxyToken, cgroupPath, containerID, interfaceName, tapMode, enforceProxy)
}

// runServerMode starts a standalone MITM proxy (no eBPF, no root required).
func runServerMode(domains, secretSpecs stringList, secretFile, proxyToken, listenAddr string) {
	// Parse secrets from flags and/or file.
	secrets, err := parseSecrets(secretSpecs)
	if err != nil {
		slog.Error("invalid --secret flag", "error", err)
		os.Exit(1)
	}
	if secretFile != "" {
		fileSecrets, err := parseSecretFileAsProxySecrets(secretFile)
		if err != nil {
			slog.Error("invalid --secret-file", "error", err)
			os.Exit(1)
		}
		secrets = append(secrets, fileSecrets...)
	}

	// Auto-generate a token if none provided and we're listening beyond localhost.
	if proxyToken == "" && !strings.HasPrefix(listenAddr, "127.0.0.1:") && !strings.HasPrefix(listenAddr, "localhost:") {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			slog.Error("failed to generate proxy token", "error", err)
			os.Exit(1)
		}
		proxyToken = hex.EncodeToString(b)
		slog.Warn("no --proxy-token set for non-localhost listener, auto-generated token", "token", proxyToken)
	}

	ca, err := proxy.GenerateCA()
	if err != nil {
		slog.Error("failed to generate CA", "error", err)
		os.Exit(1)
	}

	// Write CA cert to a predictable path for clients to use.
	caCertFile, err := proxy.WriteCombinedCACert(ca.PEM)
	if err != nil {
		slog.Error("failed to write CA cert", "error", err)
		os.Exit(1)
	}
	defer os.Remove(caCertFile)

	domainList := []string(domains)

	// Auto-add secret hosts to the domain allow list.
	allDomains := make(map[string]bool)
	for _, d := range domainList {
		allDomains[d] = true
	}
	for _, s := range secrets {
		for _, h := range s.Hosts {
			if !allDomains[h] {
				allDomains[h] = true
				slog.Debug("auto-added secret host to allow list", "host", h)
			}
		}
	}
	domainList = make([]string, 0, len(allDomains))
	for d := range allDomains {
		domainList = append(domainList, d)
	}

	var injector *proxy.Injector
	if len(secrets) > 0 {
		injector = proxy.NewInjector(secrets)
	}

	var opts []proxy.Option
	if proxyToken != "" {
		opts = append(opts, proxy.WithAuthToken(proxyToken))
	}

	proxyServer := proxy.NewServer(listenAddr, ca, injector, domainList, "", opts...)
	proxyAddr, err := proxyServer.Start()
	if err != nil {
		slog.Error("failed to start proxy", "error", err)
		os.Exit(1)
	}
	defer proxyServer.Close()

	slog.Info("proxy server started",
		"addr", proxyAddr,
		"ca_cert", caCertFile,
		"domains", len(domainList),
		"secrets", len(secrets),
		"auth", proxyToken != "",
	)

	// Block until signal.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()
	<-ctx.Done()
}

// runAttachMode handles --cgroup and --container attach modes.
func runAttachMode(domains stringList, allowedExecs stringList, secretSpecs stringList, secretFile, proxyToken, cgroupPath, containerID, interfaceName string, tapMode, enforceProxy bool) {
	// Resolve --container to a cgroup path.
	var rt runtime.Runtime
	if containerID != "" {
		var err error
		rt, err = container.NewDocker()
		if err != nil {
			slog.Error("failed to create runtime client", "error", err)
			os.Exit(1)
		}
		defer rt.Close()

		resolved, err := rt.ResolveCgroup(context.Background(), containerID)
		if err != nil {
			slog.Error("failed to resolve container cgroup", "container", containerID, "error", err)
			os.Exit(1)
		}
		cgroupPath = resolved
		slog.Info("resolved container cgroup", "container", containerID, "cgroup", cgroupPath)
	}

	// Parse secret specs into SecretConfig structs.
	secrets, err := parseSecrets(secretSpecs)
	if err != nil {
		slog.Error("invalid --secret flag", "error", err)
		os.Exit(1)
	}
	if secretFile != "" {
		fileSecrets, err := parseSecretFileAsProxySecrets(secretFile)
		if err != nil {
			slog.Error("invalid --secret-file", "error", err)
			os.Exit(1)
		}
		secrets = append(secrets, fileSecrets...)
	}

	// Auto-add secret hosts to the domain allow list.
	allDomains := make(map[string]bool)
	for _, d := range domains {
		allDomains[d] = true
	}
	for _, s := range secrets {
		for _, h := range s.Hosts {
			if !allDomains[h] {
				allDomains[h] = true
				slog.Debug("auto-added secret host to allow list", "host", h)
			}
		}
	}
	domainList := make([]string, 0, len(allDomains))
	for d := range allDomains {
		domainList = append(domainList, d)
	}

	cfg := firewall.Config{
		Domains:      domainList,
		AllowedExecs: []string(allowedExecs),
		CgroupPath:   cgroupPath,
		Interface:    interfaceName,
		Tap:          tapMode,
		EnforceProxy: enforceProxy,
	}

	// Start the MITM proxy when secrets are configured or when the allow list is
	// proxy-enforced (the proxy is then the mandatory path for web traffic).
	var proxyServer *proxy.Server
	var caCertFile string
	if len(secrets) > 0 || enforceProxy {
		ca, err := proxy.GenerateCA()
		if err != nil {
			slog.Error("failed to generate CA", "error", err)
			os.Exit(1)
		}

		// Write combined CA cert file (system CAs + our ephemeral CA).
		caCertFile, err = proxy.WriteCombinedCACert(ca.PEM)
		if err != nil {
			slog.Error("failed to write CA cert", "error", err)
			os.Exit(1)
		}
		defer os.Remove(caCertFile)

		// Write just our ephemeral CA cert separately (keytool needs a single cert, not a bundle).
		rawCAFile, err := os.CreateTemp("", "netleash-ca-raw-*.pem")
		if err != nil {
			slog.Error("failed to write raw CA cert", "error", err)
			os.Exit(1)
		}
		rawCAFile.Write(ca.PEM)
		rawCAFile.Close()
		defer os.Remove(rawCAFile.Name())

		injector := proxy.NewInjector(secrets)

		// Bind the proxy to an address reachable by the target workload.
		proxyListenAddr := "127.0.0.1:0"
		var containerIP string
		if containerID != "" {
			// Container mode: bind to the Docker bridge gateway IP.
			gatewayIP, err := rt.GetGateway(context.Background(), containerID)
			if err != nil {
				slog.Error("failed to get container gateway", "error", err)
				os.Exit(1)
			}
			proxyListenAddr = gatewayIP + ":0"

			// Get the container's IP to restrict proxy access (multitenancy isolation).
			containerIP, err = rt.GetIP(context.Background(), containerID)
			if err != nil {
				slog.Error("failed to get container IP", "error", err)
				os.Exit(1)
			}
			slog.Debug("container IP for proxy ACL", "ip", containerIP)
		} else if interfaceName != "" {
			// Interface mode: bind to the interface's IP so the VM can reach the proxy.
			iface, err := net.InterfaceByName(interfaceName)
			if err != nil {
				slog.Error("failed to look up interface", "interface", interfaceName, "error", err)
				os.Exit(1)
			}
			addrs, err := iface.Addrs()
			if err != nil {
				slog.Error("failed to get interface addresses", "interface", interfaceName, "error", err)
				os.Exit(1)
			}
			for _, addr := range addrs {
				if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.To4() != nil {
					proxyListenAddr = ipNet.IP.String() + ":0"
					break
				}
			}
		}

		var proxyOpts []proxy.Option
		if proxyToken != "" {
			proxyOpts = append(proxyOpts, proxy.WithAuthToken(proxyToken))
		}
		proxyServer = proxy.NewServer(proxyListenAddr, ca, injector, domainList, containerIP, proxyOpts...)

		proxyAddr, err := proxyServer.Start()
		if err != nil {
			slog.Error("failed to start proxy", "error", err)
			os.Exit(1)
		}
		defer proxyServer.Close()

		cfg.ProxyAddr = proxyAddr
		cfg.CACertFile = caCertFile

		// Create a Java truststore (system CAs + our CA) for JVM applications.
		if javaTrustStore := proxy.CreateJavaTrustStore(rawCAFile.Name()); javaTrustStore != "" {
			cfg.JavaTrustStore = javaTrustStore
			defer os.Remove(javaTrustStore)
			slog.Debug("JVM truststore created", "path", javaTrustStore)
		}

		// Build the placeholder env map.
		cfg.SecretsEnv = make(map[string]string)
		for _, s := range secrets {
			cfg.SecretsEnv[s.Name] = s.Placeholder
		}

		// In container mode, inject env vars and CA cert into the container.
		if containerID != "" {
			envSecrets := make([]runtime.SecretEnv, len(secrets))
			for i, s := range secrets {
				envSecrets[i] = runtime.SecretEnv{Name: s.Name, Placeholder: s.Placeholder}
			}
			if err := rt.InjectEnv(context.Background(), containerID, runtime.EnvConfig{
				Secrets:    envSecrets,
				ProxyAddr:  proxyAddr,
				CACertFile: caCertFile,
				RawCACert:  rawCAFile.Name(),
			}); err != nil {
				slog.Error("failed to inject env into container", "error", err)
				os.Exit(1)
			}
			defer rt.CleanupEnv(context.Background(), containerID)
		}

		slog.Info("MITM proxy active", "addr", proxyAddr, "secrets", len(secrets), "ca_cert", caCertFile)

		// In standalone attach/interface mode (no container), print the env vars
		// the user needs to configure manually in the target workload.
		if containerID == "" {
			fmt.Fprintln(os.Stderr, "\n# Configure your workload with these environment variables:")
			for _, s := range secrets {
				fmt.Fprintf(os.Stderr, "export %s='%s'\n", s.Name, s.Placeholder)
			}
			fmt.Fprintf(os.Stderr, "export HTTPS_PROXY='http://%s'\n", proxyAddr)
			fmt.Fprintf(os.Stderr, "export HTTP_PROXY='http://%s'\n", proxyAddr)
			fmt.Fprintf(os.Stderr, "export SSL_CERT_FILE='%s'\n", caCertFile)
			fmt.Fprintln(os.Stderr)
		}
	}

	fw := firewall.New(cfg)

	if err := fw.Setup(); err != nil {
		slog.Error("setup failed", "error", err)
		os.Exit(1)
	}
	defer fw.Cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle signals for clean shutdown.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	slog.Info("firewall active", "domains", cfg.Domains)
	if interfaceName != "" {
		slog.Info("attached to interface (Ctrl+C to detach)", "interface", interfaceName, "tap", tapMode)
	} else {
		slog.Info("attached to cgroup (Ctrl+C to detach)", "cgroup", cgroupPath)
	}
	fw.Wait(ctx)

	_ = proxyServer // keep reference for defer
	_ = caCertFile  // keep reference for defer
}

// parseSecretFlags parses --secret NAME=VALUE:host1,host2 flags into jail.Secret structs.
func parseSecretFlags(specs []string) ([]jail.Secret, error) {
	var secrets []jail.Secret

	for _, spec := range specs {
		colonIdx := strings.LastIndex(spec, ":")
		if colonIdx == -1 {
			return nil, fmt.Errorf("invalid secret format %q: expected NAME=VALUE:host1,host2", spec)
		}

		nameValue := spec[:colonIdx]
		hostList := spec[colonIdx+1:]

		eqIdx := strings.Index(nameValue, "=")
		if eqIdx == -1 {
			return nil, fmt.Errorf("invalid secret format %q: expected NAME=VALUE:host1,host2", spec)
		}

		name := nameValue[:eqIdx]
		value := nameValue[eqIdx+1:]
		hosts := strings.Split(hostList, ",")

		if name == "" || value == "" || len(hosts) == 0 || hosts[0] == "" {
			return nil, fmt.Errorf("invalid secret format %q: name, value, and hosts are all required", spec)
		}

		secrets = append(secrets, jail.Secret{
			Name:  name,
			Value: value,
			Hosts: hosts,
		})

		slog.Debug("secret configured", "name", name, "hosts", hosts)
	}

	return secrets, nil
}

// parseSecrets parses --secret flags into proxy.SecretConfig structs (used for attach mode).
func parseSecrets(specs []string) ([]proxy.SecretConfig, error) {
	var secrets []proxy.SecretConfig

	for _, spec := range specs {
		colonIdx := strings.LastIndex(spec, ":")
		if colonIdx == -1 {
			return nil, fmt.Errorf("invalid secret format %q: expected NAME=VALUE:host1,host2", spec)
		}

		nameValue := spec[:colonIdx]
		hostList := spec[colonIdx+1:]

		eqIdx := strings.Index(nameValue, "=")
		if eqIdx == -1 {
			return nil, fmt.Errorf("invalid secret format %q: expected NAME=VALUE:host1,host2", spec)
		}

		name := nameValue[:eqIdx]
		value := nameValue[eqIdx+1:]
		hosts := strings.Split(hostList, ",")

		if name == "" || value == "" || len(hosts) == 0 || hosts[0] == "" {
			return nil, fmt.Errorf("invalid secret format %q: name, value, and hosts are all required", spec)
		}

		secrets = append(secrets, proxy.SecretConfig{
			Name:        name,
			Placeholder: proxy.GeneratePlaceholder(),
			Value:       value,
			Hosts:       hosts,
		})

		slog.Debug("secret configured", "name", name, "hosts", hosts, "placeholder_len", len(secrets[len(secrets)-1].Placeholder))
	}

	return secrets, nil
}

// parseSecretFile reads secrets from a file (or stdin if path is "-").
// Each line is in the same NAME=VALUE:host1,host2 format as --secret.
// Empty lines and lines starting with # are skipped.
func parseSecretFile(path string) ([]string, error) {
	var r *os.File
	if path == "-" {
		r = os.Stdin
	} else {
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("opening secret file: %w", err)
		}
		defer f.Close()
		r = f

		// Warn if the file is world-readable.
		if info, err := f.Stat(); err == nil {
			if info.Mode()&0044 != 0 {
				slog.Warn("secret file is readable by group/others", "path", path, "mode", info.Mode().String())
			}
		}
	}

	var specs []string
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		specs = append(specs, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading secret file: %w", err)
	}
	return specs, nil
}

// parseSecretFileAsJailSecrets reads a secret file and returns jail.Secret structs.
func parseSecretFileAsJailSecrets(path string) ([]jail.Secret, error) {
	specs, err := parseSecretFile(path)
	if err != nil {
		return nil, err
	}
	return parseSecretFlags(specs)
}

// parseSecretFileAsProxySecrets reads a secret file and returns proxy.SecretConfig structs.
func parseSecretFileAsProxySecrets(path string) ([]proxy.SecretConfig, error) {
	specs, err := parseSecretFile(path)
	if err != nil {
		return nil, err
	}
	return parseSecrets(specs)
}
