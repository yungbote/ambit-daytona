package firewall

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// isTCMode returns true if the firewall is in TC/interface mode.
func (fw *Firewall) isTCMode() bool {
	return fw.cfg.Interface != ""
}

const cgroupBase = "/sys/fs/cgroup"

// Config holds all configuration for the firewall.
type Config struct {
	Domains          []string                                         // whitelisted domains for egress
	InternalDNSZones []string                                         // cluster-internal DNS zones (e.g. "cluster.local") whose queries pass through to the resolver
	AllowedExecs     []string                                         // whitelisted executable paths (empty = no exec filtering)
	ProxyAddr        string                                           // "127.0.0.1:18080" (empty = no proxy)
	EnforceProxy     bool                                             // gate web ports (TCP 80/443, UDP 443) so HTTP(S) can only reach ProxyAddr — the hostname-aware proxy becomes the mandatory egress path for web traffic
	SecretsEnv       map[string]string                                // env var NAME → placeholder value
	CACertFile       string                                           // path to combined CA cert file
	JavaTrustStore   string                                           // path to PKCS12 keystore for JVM TLS (empty = no JVM truststore)
	CgroupPath       string                                           // attach to existing cgroup (empty = create new) — cgroup mode
	PinPath          string                                           // bpffs dir to pin links+maps (empty = no pinning) — cgroup mode; survives a restart of this process
	Interface        string                                           // network interface name (e.g., "tap0", "veth0") — TC mode
	Tap              bool                                             // swap TC attach directions for tap devices (use with Interface)
	Stdout           io.Writer                                        // child process stdout (nil = os.Stdout)
	Stderr           io.Writer                                        // child process stderr (nil = os.Stderr)
	Stdin            io.Reader                                        // child process stdin (nil = os.Stdin)
	Env              []string                                         // additional env vars for the child process
	User             string                                           // drop privileges to this user (e.g., "goran" or "1000")
	OnBlocked        func(dstIP string, dstPort uint16, proto string) // optional callback for blocked packets
	OnExecBlocked    func(path string)                                // optional callback for blocked exec attempts
	Logger           *slog.Logger                                     // if nil, slog.Default() is used
}

// Firewall manages the eBPF-based egress firewall for a child process.
type Firewall struct {
	cfg         Config
	log         *slog.Logger
	cgroupPath  string
	cgroupFD    int                  // file descriptor for CLONE_INTO_CGROUP
	ownsCgroup  bool                 // true if we created the cgroup (and should remove it on cleanup)
	maps        firewallMapsAccessor // uniform map access for both modes
	cgObjs      *firewallObjects     // non-nil in cgroup mode
	tcObjs      *firewallTcObjects   // non-nil in TC mode
	lsmObjs     *firewallLsmObjects  // non-nil when exec filtering is active
	egressLink  link.Link
	ingressLink link.Link
	// connect4Link / getpeernameLink attach the transparent-redirect programs
	// (cgroup mode only). They redirect web-port connect() to the enforcement
	// proxy and restore the original peer for getpeername(). Nil in TC mode and
	// when adopted from a pin set that predates transparent redirect;
	// getpeernameLink is additionally nil on kernels < 5.8, which lack the
	// getpeername4 attach type.
	connect4Link    link.Link
	getpeernameLink link.Link
	lsmLink         link.Link
	adopted         bool        // true if re-opened from pinned objects (Adopt) rather than freshly attached
	pinnedMaps      []*ebpf.Map // maps re-opened during Adopt (closed on teardown)
}

// Pin filenames under Config.PinPath for the cgroup-mode firewall.
const (
	pinEgressLink       = "egress_link"
	pinIngressLink      = "ingress_link"
	pinConnect4Link     = "connect4_link"
	pinGetpeernameLink  = "getpeername4_link"
	pinAllowedDomains   = "allowed_domains"
	pinAllowedWildcards = "allowed_wildcards"
	pinAllowedIps       = "allowed_ips"
	pinInternalZones    = "internal_dns_zones"
	pinEvents           = "events"
	pinProxyConfig      = "proxy_config"
)

// New creates a new Firewall with the given configuration.
func New(cfg Config) *Firewall {
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	return &Firewall{
		cfg:      cfg,
		log:      log,
		cgroupFD: -1,
	}
}

// Setup loads eBPF programs and attaches them. In cgroup mode (default), it
// creates or attaches to a cgroup. In TC mode (when Interface is set), it
// attaches TC programs to the specified network interface.
func (fw *Firewall) Setup() error {
	if fw.cfg.Interface != "" {
		return fw.setupTC()
	}
	return fw.setupCgroup()
}

// kernelSupportsGetpeername4 reports whether the running kernel accepts cgroup
// sock_addr programs with the BPF_CGROUP_INET4_GETPEERNAME attach type
// (introduced in Linux 5.8; the documented minimum kernel for cgroup mode is
// 5.7). Probed by loading a minimal program: older kernels reject the attach
// type at load time.
func kernelSupportsGetpeername4() bool {
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:       ebpf.CGroupSockAddr,
		AttachType: ebpf.AttachCgroupInet4GetPeername,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 1),
			asm.Return(),
		},
		License: "GPL",
	})
	if err != nil {
		return false
	}
	prog.Close()
	return true
}

// setupCgroup creates or attaches to a cgroup, loads cgroup_skb programs, and attaches them.
func (fw *Firewall) setupCgroup() error {
	if fw.cfg.CgroupPath != "" {
		// Attach to an existing cgroup.
		info, err := os.Stat(fw.cfg.CgroupPath)
		if err != nil || !info.IsDir() {
			return fmt.Errorf("cgroup path does not exist: %s", fw.cfg.CgroupPath)
		}
		fw.cgroupPath = fw.cfg.CgroupPath
		fw.ownsCgroup = false
		fw.log.Debug("attaching to existing cgroup", "path", fw.cgroupPath)
	} else {
		// Create a new cgroup for this firewall instance.
		fw.cgroupPath = filepath.Join(cgroupBase, fmt.Sprintf("netleash-%d", os.Getpid()))
		if err := os.MkdirAll(fw.cgroupPath, 0755); err != nil {
			return fmt.Errorf("creating cgroup %s: %w", fw.cgroupPath, err)
		}
		fw.ownsCgroup = true
		fw.log.Debug("created cgroup", "path", fw.cgroupPath)

		// Open a file descriptor for CLONE_INTO_CGROUP (only needed when spawning children).
		fd, err := syscall.Open(fw.cgroupPath, syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
		if err != nil {
			return fmt.Errorf("opening cgroup fd: %w", err)
		}
		fw.cgroupFD = fd
	}

	// Load the compiled eBPF objects (programs + maps). The getpeername4
	// program's attach type (BPF_CGROUP_INET4_GETPEERNAME) only exists on Linux
	// ≥ 5.8, while the documented minimum kernel is 5.7 — on older kernels the
	// program is stripped from the spec before loading (the kernel would reject
	// the whole collection otherwise). Everything else, including the connect4
	// redirect, still works; workloads there merely see the proxy's address from
	// getpeername() on redirected sockets.
	var objs firewallObjects
	if kernelSupportsGetpeername4() {
		if err := loadFirewallObjects(&objs, nil); err != nil {
			return fmt.Errorf("loading eBPF objects: %w", err)
		}
	} else {
		fw.log.Warn("kernel lacks cgroup/getpeername4 (Linux < 5.8); redirected sockets will observe the proxy address from getpeername()")
		spec, err := loadFirewall()
		if err != nil {
			return fmt.Errorf("loading eBPF collection spec: %w", err)
		}
		delete(spec.Programs, "firewall_getpeername4")
		var partial struct {
			firewallMaps
			FirewallConnect4   *ebpf.Program `ebpf:"firewall_connect4"`
			FirewallDnsIngress *ebpf.Program `ebpf:"firewall_dns_ingress"`
			FirewallEgress     *ebpf.Program `ebpf:"firewall_egress"`
		}
		if err := spec.LoadAndAssign(&partial, nil); err != nil {
			return fmt.Errorf("loading eBPF objects: %w", err)
		}
		objs.firewallMaps = partial.firewallMaps
		objs.FirewallConnect4 = partial.FirewallConnect4
		objs.FirewallDnsIngress = partial.FirewallDnsIngress
		objs.FirewallEgress = partial.FirewallEgress
	}
	fw.cgObjs = &objs
	fw.maps = firewallMapsAccessor{
		AllowedDomains:   objs.AllowedDomains,
		AllowedIps:       objs.AllowedIps,
		AllowedWildcards: objs.AllowedWildcards,
		InternalDNSZones: objs.InternalDnsZones,
		Events:           objs.Events,
		ProxyConfig:      objs.ProxyConfig,
	}

	// Attach the cgroup_skb/egress program (domain firewall).
	el, err := link.AttachCgroup(link.CgroupOptions{
		Path:    fw.cgroupPath,
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: objs.FirewallEgress,
	})
	if err != nil {
		return fmt.Errorf("attaching eBPF egress to cgroup: %w", err)
	}
	fw.egressLink = el

	// Attach the cgroup_skb/ingress program (DNS response interception).
	il, err := link.AttachCgroup(link.CgroupOptions{
		Path:    fw.cgroupPath,
		Attach:  ebpf.AttachCGroupInetIngress,
		Program: objs.FirewallDnsIngress,
	})
	if err != nil {
		el.Close()
		return fmt.Errorf("attaching eBPF ingress to cgroup: %w", err)
	}
	fw.ingressLink = il

	// Attach the transparent-redirect programs: cgroup/connect4 rewrites web-port
	// connect() to the enforcement proxy so clients that ignore HTTP(S)_PROXY still
	// route through it, and cgroup/getpeername4 restores the original peer for
	// getpeername(). Both consult proxy_config, so they are inert until proxy
	// enforcement is turned on — attaching them unconditionally keeps the pin set
	// uniform (enforcement can be toggled in place afterwards).
	c4, err := link.AttachCgroup(link.CgroupOptions{
		Path:    fw.cgroupPath,
		Attach:  ebpf.AttachCGroupInet4Connect,
		Program: objs.FirewallConnect4,
	})
	if err != nil {
		il.Close()
		el.Close()
		return fmt.Errorf("attaching eBPF connect4 to cgroup: %w", err)
	}
	fw.connect4Link = c4

	// getpeername4 is nil on kernels without BPF_CGROUP_INET4_GETPEERNAME
	// (Linux < 5.8); the pin/adopt paths already tolerate its absence.
	if objs.FirewallGetpeername4 != nil {
		gp, err := link.AttachCgroup(link.CgroupOptions{
			Path:    fw.cgroupPath,
			Attach:  ebpf.AttachCgroupInet4GetPeername,
			Program: objs.FirewallGetpeername4,
		})
		if err != nil {
			c4.Close()
			il.Close()
			el.Close()
			return fmt.Errorf("attaching eBPF getpeername4 to cgroup: %w", err)
		}
		fw.getpeernameLink = gp
	}
	fw.log.Debug("eBPF programs attached to cgroup")

	// Populate the allowed_domains eBPF map so the ingress program knows which
	// DNS responses to learn IPs from.
	if err := fw.populateAllowedDomains(); err != nil {
		return fmt.Errorf("populating allowed domains: %w", err)
	}

	// Seed cluster-internal DNS zones whose queries are passed through to the
	// resolver (so Kubernetes search-domain expansion doesn't stall).
	if err := fw.populateInternalDNSZones(); err != nil {
		return fmt.Errorf("populating internal DNS zones: %w", err)
	}

	// Allow the proxy IP in the egress filter (if proxy is configured).
	if err := fw.allowProxyIP(); err != nil {
		return fmt.Errorf("allowing proxy IP: %w", err)
	}

	// Seed the egress-proxy gate (proxy IP:port + enforce flag).
	if err := fw.populateProxyConfig(); err != nil {
		return fmt.Errorf("populating proxy config: %w", err)
	}

	// Pin links + maps to bpffs so the filter survives a restart of this
	// process (pinned cgroup links stay attached with no userspace owner).
	if fw.cfg.PinPath != "" {
		if err := fw.pinFirewall(); err != nil {
			fw.Detach() // best-effort: remove any partial pins + detach
			return fmt.Errorf("pinning firewall: %w", err)
		}
	}

	// If exec filtering is configured, load and attach LSM program.
	if len(fw.cfg.AllowedExecs) > 0 {
		if err := fw.setupLSM(); err != nil {
			return fmt.Errorf("setting up exec filter: %w", err)
		}
	}

	return nil
}

// setupLSM loads the LSM eBPF program for exec filtering and attaches it globally.
// Filtering is scoped to the target cgroup via bpf_get_current_cgroup_id().
func (fw *Firewall) setupLSM() error {
	var objs firewallLsmObjects
	if err := loadFirewallLsmObjects(&objs, nil); err != nil {
		return fmt.Errorf("loading LSM eBPF objects: %w (is CONFIG_BPF_LSM=y and 'bpf' in the kernel LSM list?)", err)
	}
	fw.lsmObjs = &objs

	// Attach LSM program globally.
	ll, err := link.AttachLSM(link.LSMOptions{
		Program: objs.ExecFilter,
	})
	if err != nil {
		objs.Close()
		fw.lsmObjs = nil
		return fmt.Errorf("attaching LSM exec filter: %w", err)
	}
	fw.lsmLink = ll

	// Store the target cgroup ID so the BPF program only filters our cgroup.
	cgroupID, err := getCgroupID(fw.cgroupPath)
	if err != nil {
		return fmt.Errorf("getting cgroup ID: %w", err)
	}
	if err := objs.TargetCgroupId.Put(uint32(0), cgroupID); err != nil {
		return fmt.Errorf("setting target cgroup ID: %w", err)
	}
	fw.log.Debug("LSM exec filter target cgroup", "id", cgroupID, "path", fw.cgroupPath)

	// Populate the allowed_execs map.
	if err := fw.populateAllowedExecs(); err != nil {
		return fmt.Errorf("populating allowed execs: %w", err)
	}

	fw.log.Debug("LSM exec filter attached", "allowed_execs", len(fw.cfg.AllowedExecs))
	return nil
}

// setupTC loads TC eBPF programs and attaches them to the configured network interface.
func (fw *Firewall) setupTC() error {
	iface, err := net.InterfaceByName(fw.cfg.Interface)
	if err != nil {
		return fmt.Errorf("looking up interface %q: %w", fw.cfg.Interface, err)
	}

	var objs firewallTcObjects
	if err := loadFirewallTcObjects(&objs, nil); err != nil {
		return fmt.Errorf("loading TC eBPF objects: %w", err)
	}
	fw.tcObjs = &objs
	fw.maps = firewallMapsAccessor{
		AllowedDomains:   objs.AllowedDomains,
		AllowedIps:       objs.AllowedIps,
		AllowedWildcards: objs.AllowedWildcards,
		InternalDNSZones: objs.InternalDnsZones,
		Events:           objs.Events,
		ProxyConfig:      objs.ProxyConfig,
	}

	// Determine attachment directions. On tap devices, TC directions are
	// inverted relative to the VM's perspective: VM egress arrives as
	// ingress on the tap, and DNS responses to the VM are egress on the tap.
	egressAttach := ebpf.AttachTCXEgress
	ingressAttach := ebpf.AttachTCXIngress
	if fw.cfg.Tap {
		egressAttach = ebpf.AttachTCXIngress
		ingressAttach = ebpf.AttachTCXEgress
	}

	// Attach TC egress filter (blocks non-allowed traffic).
	el, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   objs.FirewallTcEgress,
		Attach:    egressAttach,
	})
	if err != nil {
		return fmt.Errorf("attaching TC egress to %s: %w", fw.cfg.Interface, err)
	}
	fw.egressLink = el

	// Attach TC ingress program (DNS response learning).
	il, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   objs.FirewallTcDnsIngress,
		Attach:    ingressAttach,
	})
	if err != nil {
		el.Close()
		return fmt.Errorf("attaching TC ingress to %s: %w", fw.cfg.Interface, err)
	}
	fw.ingressLink = il
	fw.log.Debug("TC eBPF programs attached", "interface", fw.cfg.Interface, "tap", fw.cfg.Tap)

	if err := fw.populateAllowedDomains(); err != nil {
		return fmt.Errorf("populating allowed domains: %w", err)
	}
	if err := fw.populateInternalDNSZones(); err != nil {
		return fmt.Errorf("populating internal DNS zones: %w", err)
	}
	if err := fw.allowProxyIP(); err != nil {
		return fmt.Errorf("allowing proxy IP: %w", err)
	}
	if err := fw.populateProxyConfig(); err != nil {
		return fmt.Errorf("populating proxy config: %w", err)
	}

	return nil
}

// Wait blocks until the context is cancelled, keeping the eBPF filter active.
// Used in attach mode when no child process is spawned.
func (fw *Firewall) Wait(ctx context.Context) {
	fw.StartEventReader(ctx)
	<-ctx.Done()
}

// RunProcess starts the child command inside the firewall's cgroup, waits for it,
// and returns its exit code. Only available in cgroup mode.
func (fw *Firewall) RunProcess(ctx context.Context, args []string) (int, error) {
	if fw.isTCMode() {
		return 1, fmt.Errorf("RunProcess is not supported in TC/interface mode")
	}
	fw.StartEventReader(ctx)

	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdin = fw.cfg.Stdin
	if cmd.Stdin == nil {
		cmd.Stdin = os.Stdin
	}
	cmd.Stdout = fw.cfg.Stdout
	if cmd.Stdout == nil {
		cmd.Stdout = os.Stdout
	}
	cmd.Stderr = fw.cfg.Stderr
	if cmd.Stderr == nil {
		cmd.Stderr = os.Stderr
	}

	// Place the child directly into our cgroup at fork time (CLONE_INTO_CGROUP).
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CgroupFD:    fw.cgroupFD,
		UseCgroupFD: true,
	}

	// Drop privileges to the specified user (run as root, jail as user).
	if fw.cfg.User != "" {
		cred, err := resolveUser(fw.cfg.User)
		if err != nil {
			return 1, fmt.Errorf("resolving user %q: %w", fw.cfg.User, err)
		}
		cmd.SysProcAttr.Credential = cred
		fw.log.Debug("dropping privileges", "user", fw.cfg.User, "uid", cred.Uid, "gid", cred.Gid)
	}

	// Start with the current environment, add caller-supplied vars, then overlay proxy/secret vars.
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, fw.cfg.Env...)

	// Inject placeholder secret env vars (child sees placeholders, not real values).
	for name, placeholder := range fw.cfg.SecretsEnv {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", name, placeholder))
	}

	// If proxy is configured, set proxy env vars so the child routes through it.
	if fw.cfg.ProxyAddr != "" {
		proxyURL := fmt.Sprintf("http://%s", fw.cfg.ProxyAddr)
		proxyHost, proxyPort, _ := net.SplitHostPort(fw.cfg.ProxyAddr)
		cmd.Env = append(cmd.Env,
			"HTTP_PROXY="+proxyURL,
			"HTTPS_PROXY="+proxyURL,
			"http_proxy="+proxyURL,
			"https_proxy="+proxyURL,
		)
		// JVM ignores *_PROXY env vars; it reads proxy settings from system properties.
		javaOpts := fmt.Sprintf("-Dhttp.proxyHost=%s -Dhttp.proxyPort=%s -Dhttps.proxyHost=%s -Dhttps.proxyPort=%s", proxyHost, proxyPort, proxyHost, proxyPort)
		if fw.cfg.JavaTrustStore != "" {
			javaOpts += fmt.Sprintf(" -Djavax.net.ssl.trustStore=%s -Djavax.net.ssl.trustStorePassword=changeit", fw.cfg.JavaTrustStore)
		}
		cmd.Env = append(cmd.Env, "JAVA_TOOL_OPTIONS="+javaOpts)
		fw.log.Debug("proxy env vars set", "proxy", proxyURL)
	}

	// If a custom CA cert file is provided, inject it for TLS trust.
	if fw.cfg.CACertFile != "" {
		cmd.Env = append(cmd.Env,
			"SSL_CERT_FILE="+fw.cfg.CACertFile,
			"NODE_EXTRA_CA_CERTS="+fw.cfg.CACertFile,
			"REQUESTS_CA_BUNDLE="+fw.cfg.CACertFile,
			"CURL_CA_BUNDLE="+fw.cfg.CACertFile,
		)
		fw.log.Debug("CA cert injected", "path", fw.cfg.CACertFile)
	}

	// Set PR_SET_NO_NEW_PRIVS on the current OS thread before fork.
	// This prevents the child from gaining privileges via setuid/setgid binaries
	// (e.g., sudo, su), which would allow escaping the cgroup jail.
	// The flag is inherited across fork+exec and cannot be unset.
	runtime.LockOSThread()
	if _, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0); errno != 0 {
		runtime.UnlockOSThread()
		return 1, fmt.Errorf("setting no_new_privs: %w", errno)
	}
	err := cmd.Start()
	runtime.UnlockOSThread()
	if err != nil {
		return 1, fmt.Errorf("starting process: %w", err)
	}

	fw.log.Debug("process started in cgroup", "pid", cmd.Process.Pid, "no_new_privs", true)

	err = cmd.Wait()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode(), nil
		}
		return 1, err
	}
	return 0, nil
}

// Pin pins an already-attached firewall's links and maps to bpffs at pinPath, so
// the egress filter survives a restart of this process. Works for both cgroup
// and TC/interface mode — pinned bpf_links keep their programs attached with no
// userspace owner regardless of attach type. Call after a successful Setup;
// Adopt re-opens the pins in the next process. Pinning after Setup (rather than
// via Config.PinPath) lets a caller swap allow lists without two firewalls
// colliding on the same pin path.
func (fw *Firewall) Pin(pinPath string) error {
	if fw.cgObjs == nil && fw.tcObjs == nil {
		return fmt.Errorf("pin requires a firewall created via Setup")
	}
	fw.cfg.PinPath = pinPath
	return fw.pinFirewall()
}

// pinFirewall pins the egress/ingress links and the maps needed for management
// to bpffs under fw.cfg.PinPath. Pinned links keep the programs attached to the
// cgroup (cgroup mode) or interface (TC mode) even with no userspace owner, so
// the egress filter survives a restart of this process (Adopt re-opens them,
// zero gap). PinPath must live on a bpffs mount (e.g. /sys/fs/bpf) that persists
// across the restart — on bare metal this is the host's own bpffs.
func (fw *Firewall) pinFirewall() error {
	if err := os.MkdirAll(fw.cfg.PinPath, 0o700); err != nil {
		return fmt.Errorf("creating pin dir %s: %w", fw.cfg.PinPath, err)
	}
	// Pin atomically: if any individual pin fails, remove the whole directory so
	// we never leave a partial pin set behind. A partial set (e.g. egress pinned
	// but ingress not) would survive a restart — keeping a half-attached filter
	// alive — yet be un-adoptable, since Adopt needs every pin. Rolling back
	// leaves the in-process links attached (the filter keeps working this
	// session) but unpinned, so the worst case is simply "won't survive a
	// restart" rather than a broken, stuck state.
	if err := fw.pinAll(); err != nil {
		if rmErr := os.RemoveAll(fw.cfg.PinPath); rmErr != nil {
			fw.log.Warn("failed to roll back partial pins", "path", fw.cfg.PinPath, "error", rmErr)
		}
		return err
	}
	fw.log.Debug("pinned firewall", "path", fw.cfg.PinPath)
	return nil
}

// pinAll pins the links and the maps Adopt needs. On the first failure it
// returns immediately; pinFirewall is responsible for cleaning up partial state.
func (fw *Firewall) pinAll() error {
	if err := fw.egressLink.Pin(filepath.Join(fw.cfg.PinPath, pinEgressLink)); err != nil {
		return fmt.Errorf("pinning egress link: %w", err)
	}
	if err := fw.ingressLink.Pin(filepath.Join(fw.cfg.PinPath, pinIngressLink)); err != nil {
		return fmt.Errorf("pinning ingress link: %w", err)
	}
	// connect4/getpeername4 exist only in cgroup mode; skip in TC mode where they
	// are nil. Pinning them keeps transparent redirect attached across a restart.
	if fw.connect4Link != nil {
		if err := fw.connect4Link.Pin(filepath.Join(fw.cfg.PinPath, pinConnect4Link)); err != nil {
			return fmt.Errorf("pinning connect4 link: %w", err)
		}
	}
	if fw.getpeernameLink != nil {
		if err := fw.getpeernameLink.Pin(filepath.Join(fw.cfg.PinPath, pinGetpeernameLink)); err != nil {
			return fmt.Errorf("pinning getpeername4 link: %w", err)
		}
	}
	for name, m := range fw.pinnableMaps() {
		if err := m.Pin(filepath.Join(fw.cfg.PinPath, name)); err != nil {
			return fmt.Errorf("pinning map %s: %w", name, err)
		}
	}
	return nil
}

// pinnableMaps returns the maps that Adopt needs to re-open, keyed by pin
// filename. It reads from the uniform maps accessor (populated identically in
// cgroup and TC mode), so the same set is pinned regardless of attach type. The
// other maps (reported_ips, inbound_conns) are managed entirely in-kernel and
// stay alive via the pinned programs, so they need no userspace handle after a
// restart.
func (fw *Firewall) pinnableMaps() map[string]*ebpf.Map {
	return map[string]*ebpf.Map{
		pinAllowedDomains:   fw.maps.AllowedDomains,
		pinAllowedWildcards: fw.maps.AllowedWildcards,
		pinAllowedIps:       fw.maps.AllowedIps,
		pinInternalZones:    fw.maps.InternalDNSZones,
		pinEvents:           fw.maps.Events,
		pinProxyConfig:      fw.maps.ProxyConfig,
	}
}

// Adopt re-opens a firewall previously pinned to fw.cfg.PinPath by an earlier
// process, instead of attaching a fresh one. It is attach-type agnostic: the
// pinned links (cgroup or TC) keep the programs attached across the restart
// (zero gap), and the pinned maps are the same set in both modes, so Adopt just
// restores the userspace handles so the event reader and allow-list maps can be
// managed again. The caller is responsible for verifying the underlying
// cgroup/interface/workload still exists.
func (fw *Firewall) Adopt() error {
	if fw.cfg.PinPath == "" {
		return fmt.Errorf("adopt requires PinPath")
	}
	el, err := link.LoadPinnedLink(filepath.Join(fw.cfg.PinPath, pinEgressLink), nil)
	if err != nil {
		return fmt.Errorf("loading pinned egress link: %w", err)
	}
	fw.egressLink = el
	il, err := link.LoadPinnedLink(filepath.Join(fw.cfg.PinPath, pinIngressLink), nil)
	if err != nil {
		fw.Cleanup()
		return fmt.Errorf("loading pinned ingress link: %w", err)
	}
	fw.ingressLink = il

	// connect4/getpeername4 links were added with transparent redirect. A pin set
	// written by an older version doesn't have them — tolerate their absence (the
	// egress program still enforces via its drop path) rather than failing the
	// whole adoption, which would tear down a working filter.
	if c4, err := link.LoadPinnedLink(filepath.Join(fw.cfg.PinPath, pinConnect4Link), nil); err == nil {
		fw.connect4Link = c4
	} else if !os.IsNotExist(err) {
		fw.Cleanup()
		return fmt.Errorf("loading pinned connect4 link: %w", err)
	} else {
		fw.log.Warn("pinned firewall predates transparent redirect; web egress falls back to the drop path until rebuilt")
	}
	if gp, err := link.LoadPinnedLink(filepath.Join(fw.cfg.PinPath, pinGetpeernameLink), nil); err == nil {
		fw.getpeernameLink = gp
	} else if !os.IsNotExist(err) {
		fw.Cleanup()
		return fmt.Errorf("loading pinned getpeername4 link: %w", err)
	}

	for _, name := range []string{pinAllowedDomains, pinAllowedWildcards, pinAllowedIps, pinInternalZones, pinEvents, pinProxyConfig} {
		m, err := ebpf.LoadPinnedMap(filepath.Join(fw.cfg.PinPath, name), nil)
		if err != nil {
			// Every adopted domain policy must carry the hostname-enforcement map.
			// Accepting an older pin set here would silently revive the shared-IP/SNI
			// bypass. Cleanup closes only this process's handles and deliberately
			// leaves the still-enforcing pins for the runner to quarantine/stop.
			fw.Cleanup()
			return fmt.Errorf("loading pinned map %s: %w", name, err)
		}
		fw.pinnedMaps = append(fw.pinnedMaps, m)
		switch name {
		case pinAllowedDomains:
			fw.maps.AllowedDomains = m
		case pinAllowedWildcards:
			fw.maps.AllowedWildcards = m
		case pinAllowedIps:
			fw.maps.AllowedIps = m
		case pinInternalZones:
			fw.maps.InternalDNSZones = m
		case pinEvents:
			fw.maps.Events = m
		case pinProxyConfig:
			fw.maps.ProxyConfig = m
		}
	}

	fw.adopted = true
	fw.cgroupPath = fw.cfg.CgroupPath
	fw.log.Debug("adopted pinned cgroup firewall", "path", fw.cfg.PinPath)
	return nil
}

// Cleanup releases this process's handles to the firewall but LEAVES any bpffs
// pins in place, so a pinned cgroup filter keeps running uninterrupted across a
// restart of this process (zero gap). Use Detach to tear the filter down.
func (fw *Firewall) Cleanup() { fw.teardown(false) }

// Detach tears the firewall down for good: it removes the bpffs pins — which
// detaches the eBPF programs from the cgroup — in addition to releasing
// handles. Use when the workload is gone (sandbox stopped/destroyed).
func (fw *Firewall) Detach() { fw.teardown(true) }

// teardown closes all in-process handles. When unpin is true it also removes
// the bpffs pin directory, dropping the kernel references so the programs
// detach; when false the pins (and thus the attachment) are left intact.
func (fw *Firewall) teardown(unpin bool) {
	if fw.egressLink != nil {
		fw.egressLink.Close()
	}
	if fw.ingressLink != nil {
		fw.ingressLink.Close()
	}
	if fw.connect4Link != nil {
		fw.connect4Link.Close()
	}
	if fw.getpeernameLink != nil {
		fw.getpeernameLink.Close()
	}
	if fw.lsmLink != nil {
		fw.lsmLink.Close()
	}

	if fw.cgObjs != nil {
		fw.cgObjs.Close()
	}
	if fw.tcObjs != nil {
		fw.tcObjs.Close()
	}
	if fw.lsmObjs != nil {
		fw.lsmObjs.Close()
	}
	for _, m := range fw.pinnedMaps {
		if m != nil {
			m.Close()
		}
	}

	if fw.cgroupFD >= 0 {
		syscall.Close(fw.cgroupFD)
		fw.cgroupFD = -1
	}

	if unpin && fw.cfg.PinPath != "" {
		// Removing the bpffs pin files drops the kernel references; once the
		// fds above are also closed the links (and their programs) are freed
		// and detached from the cgroup.
		if err := os.RemoveAll(fw.cfg.PinPath); err != nil {
			fw.log.Warn("failed to remove firewall pin dir", "path", fw.cfg.PinPath, "error", err)
		}
	}

	if fw.ownsCgroup && fw.cgroupPath != "" {
		os.Remove(fw.cgroupPath)
		fw.log.Debug("cleaned up cgroup", "path", fw.cgroupPath)
	}
}

// getCgroupID returns the kernel cgroup ID for the given cgroup path.
// This matches what bpf_get_current_cgroup_id() returns in-kernel.
func getCgroupID(cgroupPath string) (uint64, error) {
	var stat unix.Stat_t
	if err := unix.Stat(cgroupPath, &stat); err != nil {
		return 0, fmt.Errorf("stat %s: %w", cgroupPath, err)
	}
	return stat.Ino, nil
}

// resolveUser looks up a user by name or numeric UID and returns
// a syscall.Credential suitable for SysProcAttr.
func resolveUser(nameOrID string) (*syscall.Credential, error) {
	u, err := user.Lookup(nameOrID)
	if err != nil {
		// Try as numeric UID.
		u, err = user.LookupId(nameOrID)
		if err != nil {
			return nil, fmt.Errorf("user %q not found", nameOrID)
		}
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("parsing uid %q: %w", u.Uid, err)
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("parsing gid %q: %w", u.Gid, err)
	}
	return &syscall.Credential{
		Uid: uint32(uid),
		Gid: uint32(gid),
	}, nil
}
