package proxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"
)

// SecretConfig defines a secret that should be injected into outbound requests.
type SecretConfig struct {
	Name        string   // env var name (e.g. "OPENAI_API_KEY")
	Placeholder string   // placeholder value given to child process
	Value       string   // real secret value (never exposed to child)
	Hosts       []string // only inject for these hosts
}

// defaultResolveTimeout bounds a single resolver call so a slow/unreachable
// secret source can't stall an outbound request indefinitely.
const defaultResolveTimeout = 10 * time.Second

// Injector replaces placeholder strings with real secret values for approved
// hosts. Its secrets come either from a fixed list (NewInjector) or, for
// per-workload dynamic secrets, from a SecretResolver whose result is cached for
// a configurable TTL (NewResolvingInjector).
type Injector struct {
	// secrets is the fixed secret list for a static injector. nil/empty when a
	// resolver is used.
	secrets []SecretConfig

	// resolver, when non-nil, supplies secrets dynamically; its result is cached
	// for ttl. marker, when non-empty, is a cheap substring pre-check: outbound
	// data not containing it can't reference a secret, so the (potentially
	// network-bound) resolver is skipped entirely.
	resolver SecretResolver
	ttl      time.Duration
	marker   string

	mu        sync.Mutex
	cached    []SecretConfig
	fetchedAt time.Time
	haveCache bool
}

// NewInjector creates an Injector with a fixed set of secret configs.
func NewInjector(secrets []SecretConfig) *Injector {
	return &Injector{secrets: secrets}
}

// NewResolvingInjector creates an Injector whose secrets are resolved on demand
// via resolver and cached for ttl (a non-positive ttl falls back to a sensible
// default). marker is an optional cheap pre-check: when non-empty, request data
// that does not contain marker is passed through untouched without invoking the
// resolver — set it to the known placeholder prefix to avoid resolving secrets
// for requests that obviously carry none.
func NewResolvingInjector(resolver SecretResolver, ttl time.Duration, marker string) *Injector {
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	return &Injector{resolver: resolver, ttl: ttl, marker: marker}
}

// snapshot returns the secrets to inject. For a static injector it's the fixed
// list; for a resolving injector it's the cached result, refreshed via the
// resolver when the cache is empty or older than ttl. On a resolver error the
// last good snapshot is reused (and nil if there was none), so a transient API
// failure leaves placeholders unreplaced rather than failing the request — the
// real secret is never leaked when resolution fails.
func (inj *Injector) snapshot() []SecretConfig {
	if inj.resolver == nil {
		return inj.secrets
	}

	inj.mu.Lock()
	defer inj.mu.Unlock()

	if inj.haveCache && time.Since(inj.fetchedAt) < inj.ttl {
		return inj.cached
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultResolveTimeout)
	defer cancel()

	secrets, err := inj.resolver.Resolve(ctx)
	if err != nil {
		// Keep serving the last good snapshot (nil if none). Leave fetchedAt
		// unchanged so the next request retries instead of caching the failure.
		return inj.cached
	}

	inj.cached = secrets
	inj.fetchedAt = time.Now()
	inj.haveCache = true
	return inj.cached
}

// ReplaceBody replaces all placeholder occurrences in body with real values,
// but ONLY if the host is in the approved list for that secret.
func (inj *Injector) ReplaceBody(host string, body []byte) []byte {
	if inj.marker != "" && !bytes.Contains(body, []byte(inj.marker)) {
		return body
	}

	// Strip port from host if present.
	h := stripPort(host)

	for _, s := range inj.snapshot() {
		if !hostAllowed(h, s.Hosts) {
			continue
		}
		body = bytes.ReplaceAll(body, []byte(s.Placeholder), []byte(s.Value))
	}
	return body
}

// ReplaceString replaces placeholders in a string (used for HTTP headers).
func (inj *Injector) ReplaceString(host string, val string) string {
	if inj.marker != "" && !strings.Contains(val, inj.marker) {
		return val
	}

	h := stripPort(host)

	for _, s := range inj.snapshot() {
		if !hostAllowed(h, s.Hosts) {
			continue
		}
		val = strings.ReplaceAll(val, s.Placeholder, s.Value)
	}
	return val
}

// HasSecrets reports whether the injector may inject anything. For a resolving
// injector this is always true (the actual secrets aren't known until a request
// triggers resolution), so the proxy always routes requests through injection.
func (inj *Injector) HasSecrets() bool {
	return inj.resolver != nil || len(inj.secrets) > 0
}

// Marker returns the cheap placeholder pre-check substring, or "" if none is
// configured. The proxy uses it to detect (and warn about) requests that carry
// a secret placeholder on a channel where injection won't run (cleartext HTTP).
func (inj *Injector) Marker() string { return inj.marker }

// TargetsHost reports whether any secret this injector holds may be injected for
// host. The proxy uses it to decide, per connection, between terminating TLS
// (MITM — required to inject/scrub secrets) and splicing the connection through
// untouched. Splicing preserves end-to-end TLS, so websockets, HTTP/2/gRPC and
// certificate pinning keep working on connections to hosts with no secret
// mapped. For a resolving injector this consults the cached snapshot (refreshing
// it if stale), so an unrestricted secret ("*") makes every host a MITM target.
func (inj *Injector) TargetsHost(host string) bool {
	h := stripPort(host)
	for _, s := range inj.snapshot() {
		if s.Value == "" || s.Placeholder == "" {
			continue
		}
		if hostAllowed(h, s.Hosts) {
			return true
		}
	}
	return false
}

// responseReplacements returns the value→placeholder pairs for the secrets that
// may be injected for host, so the proxy can strip real values back out of the
// upstream response. The sandbox is supposed to only ever see placeholders;
// this upholds that even when an upstream echoes a secret back (NL-SEC-01).
func (inj *Injector) responseReplacements(host string) []replacement {
	h := stripPort(host)
	var out []replacement
	for _, s := range inj.snapshot() {
		if s.Value == "" || s.Placeholder == "" || !hostAllowed(h, s.Hosts) {
			continue
		}
		out = append(out, replacement{value: s.Value, placeholder: s.Placeholder})
	}
	return out
}

const placeholderPrefix = "__LEASH_SECRET_"

// GeneratePlaceholder creates a random placeholder string for a secret.
func GeneratePlaceholder() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%s%s__", placeholderPrefix, hex.EncodeToString(b))
}

// MatchAllHosts is the wildcard host token that lets a secret be injected for
// ANY destination host. The Daytona API documents a secret with no allowed
// hosts as unrestricted ("Omit hosts entirely for unrestricted access"); the
// runner's APIResolver maps that empty list to this token. An empty list, by
// contrast, still matches NO host (fail-closed) — so a host list that is empty
// for any other reason (e.g. a misconfigured CLI secret) is never silently sent
// everywhere.
const MatchAllHosts = "*"

// hostAllowed reports whether host matches any entry in allowed. Entries are
// matched case-insensitively; the token "*" (MatchAllHosts) matches every host;
// an entry prefixed with "*." is a wildcard that matches any subdomain of (and
// the base of) that suffix — e.g. "*.example.com" matches "api.example.com" and
// "example.com". This mirrors the proxy's domain allow-list matching so a
// secret's `hosts` accepts the same wildcard syntax the API advertises. An empty
// allow list matches nothing.
func hostAllowed(host string, allowed []string) bool {
	host = strings.ToLower(host)
	for _, a := range allowed {
		a = strings.ToLower(strings.TrimSpace(a))
		if a == "" {
			continue
		}
		if a == MatchAllHosts {
			return true // unrestricted: inject for every host
		}
		if strings.HasPrefix(a, "*.") {
			suffix := a[1:] // "*.example.com" → ".example.com"
			if host == a[2:] || strings.HasSuffix(host, suffix) {
				return true
			}
			continue
		}
		if host == a {
			return true
		}
	}
	return false
}

func stripPort(host string) string {
	if i := strings.LastIndex(host, ":"); i != -1 {
		return host[:i]
	}
	return host
}
