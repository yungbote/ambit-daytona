// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package grant

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// The contract's vector, made by Node's crypto (grant-contract-vector.mjs).
type vector struct {
	PublicKeyPem string          `json:"publicKeyPem"`
	GrantToken   string          `json:"grantToken"`
	RevokeToken  string          `json:"revokeToken"`
	Grant        json.RawMessage `json:"grant"`
}

func loadVector(t *testing.T) vector {
	t.Helper()
	raw, err := os.ReadFile("testdata/vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func ringOf(t *testing.T, pemText string) *KeyRing {
	t.Helper()
	var ring KeyRing
	if err := ring.Apply([]byte(pemText)); err != nil {
		t.Fatal(err)
	}
	return &ring
}

func at(ms int64) func() time.Time { return func() time.Time { return time.UnixMilli(ms) } }

var vectorBinding = Binding{
	Audience: "mwcc-node-01", TenantID: "85086ad0-dab6-4cab-a0dc-6d029be8be75", UserID: "11111111-2222-4333-8444-555555555555",
	ThreadID: "66666666-7777-4888-8999-aaaaaaaaaaaa", ViewID: "bv1_eyJydW5JZCI6InJ1biJ9", ViewerID: "baaaaabb-cccc-4ddd-8eee-ffff00000301",
	SandboxID: "c0ffee00-1111-4222-8333-444455556666", SessionID: "browser-session", NativeViewID: strings.Repeat("a", 64),
}

func TestTheContractVectorMadeByNodeVerifies(t *testing.T) {
	v := loadVector(t)
	verifier := Verifier{Keys: ringOf(t, v.PublicKeyPem), Audience: "mwcc-node-01", Now: at(1790000030000)}
	g, err := verifier.Grant(v.GrantToken)
	if err != nil {
		t.Fatal(err)
	}
	want := Grant{Binding: vectorBinding, IssuedAt: 1790000000000, ExpiresAt: 1790000060000, Scope: ScopeView}
	if g != want {
		t.Fatalf("grant %+v, want %+v", g, want)
	}
	r, err := verifier.Revocation(v.RevokeToken)
	if err != nil {
		t.Fatal(err)
	}
	wantRevocation := Revocation{IssuedAt: 1790000030000, Code: 4403, Selector: Selector{
		TenantID: vectorBinding.TenantID, UserID: vectorBinding.UserID, ThreadID: vectorBinding.ThreadID, ViewID: vectorBinding.ViewID}}
	if r != wantRevocation {
		t.Fatalf("revocation %+v, want %+v", r, wantRevocation)
	}
	if !r.Covers(g) {
		t.Fatal("the vector's revocation covers the vector's grant")
	}
	// The same bytes under another key, or for another edge, admit nothing.
	other := testKey("another signer")
	if _, err := (Verifier{Keys: keysOf(other), Audience: "mwcc-node-01", Now: at(1790000010000)}).Grant(v.GrantToken); !errors.Is(err, ErrSignature) {
		t.Fatalf("wrong key: %v", err)
	}
	if _, err := (Verifier{Keys: verifier.Keys, Audience: "mwcc-node-02", Now: at(1790000010000)}).Grant(v.GrantToken); !errors.Is(err, ErrAudience) {
		t.Fatalf("wrong audience: %v", err)
	}
}

type staticKeys []ed25519.PublicKey

func (k staticKeys) PublicKeys() []ed25519.PublicKey { return k }

func testKey(label string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte(label))
	return ed25519.NewKeyFromSeed(seed[:])
}

func keysOf(keys ...ed25519.PrivateKey) staticKeys {
	var public staticKeys
	for _, key := range keys {
		public = append(public, key.Public().(ed25519.PublicKey))
	}
	return public
}

// sign makes a token from exact payload text, the way the backend does.
func sign(key ed25519.PrivateKey, payload string) string {
	segment := base64.RawURLEncoding.EncodeToString([]byte(payload))
	return segment + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(segment)))
}

const now = int64(1790000010000)

// grantJSON is a valid view grant; edits replace or delete members.
func grantJSON(edits map[string]any) string {
	members := map[string]any{
		"v": 1, "typ": "grant", "aud": "mwcc-node-01", "issuedAt": now - 10000, "expiresAt": now + 50000, "scope": "view",
		"tenantId": vectorBinding.TenantID, "userId": vectorBinding.UserID, "threadId": vectorBinding.ThreadID,
		"viewId": vectorBinding.ViewID, "viewerId": vectorBinding.ViewerID, "sandboxId": vectorBinding.SandboxID,
		"sessionId": vectorBinding.SessionID, "nativeViewId": vectorBinding.NativeViewID,
	}
	for name, value := range edits {
		if value == nil {
			delete(members, name)
		} else {
			members[name] = value
		}
	}
	encoded, _ := json.Marshal(members)
	return string(encoded)
}

// raw is JSON text placed verbatim, for forms json.Marshal would not write.
type raw string

func (r raw) MarshalJSON() ([]byte, error) { return []byte(r), nil }

func TestGrantAdmission(t *testing.T) {
	key := testKey("backend")
	verifier := Verifier{Keys: keysOf(testKey("previous"), key), Audience: "mwcc-node-01", Now: at(now)}
	accepted := func(t *testing.T, payload string) Grant {
		t.Helper()
		g, err := verifier.Grant(sign(key, payload))
		if err != nil {
			t.Fatalf("%s: %v", payload, err)
		}
		return g
	}
	if g := accepted(t, grantJSON(nil)); g.Scope != ScopeView || g.Binding != vectorBinding {
		t.Fatalf("view grant %+v", g)
	}
	control := accepted(t, grantJSON(map[string]any{"scope": "control", "controllerId": "3f1c2b4a-5d6e-4f70-8a9b-0c1d2e3f4a5b"}))
	if control.Scope != ScopeControl || control.ControllerID != "3f1c2b4a-5d6e-4f70-8a9b-0c1d2e3f4a5b" {
		t.Fatalf("control grant %+v", control)
	}
	// The whole lifetime is admitted, to the millisecond, within the skew.
	accepted(t, grantJSON(map[string]any{"issuedAt": now - 1, "expiresAt": now - 1 + 60000}))
	accepted(t, grantJSON(map[string]any{"issuedAt": now + 5000, "expiresAt": now + 6000}))
	accepted(t, grantJSON(map[string]any{"expiresAt": now + 1}))
	accepted(t, grantJSON(map[string]any{"threadId": "t:1_x.y~z-" + strings.Repeat("a", 1014)}))

	for name, test := range map[string]struct {
		token string
		want  error
	}{
		"expired at its instant":      {sign(key, grantJSON(map[string]any{"expiresAt": now})), ErrExpired},
		"longer than a minute":        {sign(key, grantJSON(map[string]any{"issuedAt": now - 1, "expiresAt": now + 60000})), ErrLifetime},
		"issued in the future":        {sign(key, grantJSON(map[string]any{"issuedAt": now + 5001, "expiresAt": now + 6000})), ErrLifetime},
		"for another edge":            {sign(key, grantJSON(map[string]any{"aud": "mwcc-node-02"})), ErrAudience},
		"an unknown signer":           {sign(testKey("sandbox"), grantJSON(nil)), ErrSignature},
		"ends before it starts":       {sign(key, grantJSON(map[string]any{"expiresAt": now - 10000})), ErrMalformed},
		"an unknown member":           {sign(key, grantJSON(map[string]any{"admin": true})), ErrMalformed},
		"a missing member":            {sign(key, grantJSON(map[string]any{"threadId": nil})), ErrMalformed},
		"another version":             {sign(key, grantJSON(map[string]any{"v": 2})), ErrMalformed},
		"a revocation's type":         {sign(key, grantJSON(map[string]any{"typ": "revoke"})), ErrMalformed},
		"an unknown scope":            {sign(key, grantJSON(map[string]any{"scope": "admin"})), ErrMalformed},
		"control without controller":  {sign(key, grantJSON(map[string]any{"scope": "control"})), ErrMalformed},
		"view naming a controller":    {sign(key, grantJSON(map[string]any{"controllerId": "3f1c2b4a-5d6e-4f70-8a9b-0c1d2e3f4a5b"})), ErrMalformed},
		"a nil viewer":                {sign(key, grantJSON(map[string]any{"viewerId": "00000000-0000-0000-0000-000000000000"})), ErrMalformed},
		"an upper-case tenant":        {sign(key, grantJSON(map[string]any{"tenantId": strings.ToUpper(vectorBinding.TenantID)})), ErrMalformed},
		"a sandbox with a slash":      {sign(key, grantJSON(map[string]any{"sandboxId": "a/b"})), ErrMalformed},
		"a session of dot-dot":        {sign(key, grantJSON(map[string]any{"sessionId": ".."})), ErrMalformed},
		"a thread with a space":       {sign(key, grantJSON(map[string]any{"threadId": "a b"})), ErrMalformed},
		"a view id too long":          {sign(key, grantJSON(map[string]any{"viewId": strings.Repeat("a", 1025)})), ErrMalformed},
		"a short native view":         {sign(key, grantJSON(map[string]any{"nativeViewId": strings.Repeat("a", 63)})), ErrMalformed},
		"an integer as text":          {sign(key, grantJSON(map[string]any{"issuedAt": "1790000000000"})), ErrMalformed},
		"an integer with a fraction":  {sign(key, grantJSON(map[string]any{"v": raw("1.0")})), ErrMalformed},
		"an integer with an exponent": {sign(key, grantJSON(map[string]any{"expiresAt": raw("1.79000006e12")})), ErrMalformed},
		"a negative integer":          {sign(key, grantJSON(map[string]any{"v": raw("-1")})), ErrMalformed},
		"a leading zero":              {sign(key, grantJSON(map[string]any{"v": raw("01")})), ErrMalformed},
		"beyond 2^53-1":               {sign(key, grantJSON(map[string]any{"expiresAt": raw("9007199254740992")})), ErrMalformed},
		"a string with an escape":     {sign(key, grantJSON(map[string]any{"scope": raw(`"view"`)})), nil},
		"a duplicate member":          {sign(key, strings.Replace(grantJSON(nil), `"v":1`, `"v":1,"v":1`, 1)), ErrMalformed},
		"trailing data":               {sign(key, grantJSON(nil)+"{}"), ErrMalformed},
		"an array":                    {sign(key, "["+grantJSON(nil)+"]"), ErrMalformed},
		"invalid UTF-8":               {sign(key, strings.Replace(grantJSON(nil), "browser-session", "browser-\xffsession", 1)), ErrMalformed},
		"no signature":                {strings.Split(sign(key, grantJSON(nil)), ".")[0], ErrMalformed},
		"three segments":              {sign(key, grantJSON(nil)) + ".x", ErrMalformed},
		"a padded signature":          {sign(key, grantJSON(nil)) + "==", ErrMalformed},
		"a standard base64 payload":   {strings.Replace(sign(key, grantJSON(map[string]any{"viewId": "bv1_??>>"})), "_", "/", -1), ErrMalformed},
		"longer than the bound":       {sign(key, grantJSON(map[string]any{"viewId": strings.Repeat("a", 1024), "sandboxId": strings.Repeat("b", 1024), "threadId": strings.Repeat("c", 1024)})), ErrMalformed},
		"empty":                       {"", ErrMalformed},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := verifier.Grant(test.token)
			if !errors.Is(err, test.want) && !(test.want == nil && err == nil) {
				t.Fatalf("got %v, want %v", err, test.want)
			}
		})
	}
	// A payload whose signature covers other bytes admits nothing.
	token := sign(key, grantJSON(nil))
	segments := strings.Split(token, ".")
	forged := base64.RawURLEncoding.EncodeToString([]byte(grantJSON(map[string]any{"scope": "control", "controllerId": "3f1c2b4a-5d6e-4f70-8a9b-0c1d2e3f4a5b"})))
	if _, err := verifier.Grant(forged + "." + segments[1]); !errors.Is(err, ErrSignature) {
		t.Fatalf("forged payload: %v", err)
	}
}

func revocationJSON(edits map[string]any) string {
	members := map[string]any{"v": 1, "typ": "revoke", "issuedAt": now, "code": 4403, "tenantId": vectorBinding.TenantID}
	for name, value := range edits {
		if value == nil {
			delete(members, name)
		} else {
			members[name] = value
		}
	}
	encoded, _ := json.Marshal(members)
	return string(encoded)
}

func TestRevocationAdmission(t *testing.T) {
	key := testKey("backend")
	verifier := Verifier{Keys: keysOf(key), Audience: "mwcc-node-01", Now: at(now)}
	all := map[string]any{"userId": vectorBinding.UserID, "threadId": vectorBinding.ThreadID, "viewId": vectorBinding.ViewID,
		"viewerId": vectorBinding.ViewerID, "sandboxId": vectorBinding.SandboxID, "sessionId": vectorBinding.SessionID,
		"nativeViewId": vectorBinding.NativeViewID, "code": 4410}
	r, err := verifier.Revocation(sign(key, revocationJSON(all)))
	if err != nil || r.Code != 4410 || r.NativeViewID != vectorBinding.NativeViewID || r.IssuedAt != now {
		t.Fatalf("%+v %v", r, err)
	}
	for _, code := range []int{4401, 4403, 4404, 4410} {
		if _, err := verifier.Revocation(sign(key, revocationJSON(map[string]any{"code": code}))); err != nil {
			t.Fatalf("code %d: %v", code, err)
		}
	}
	for name, test := range map[string]struct {
		token string
		want  error
	}{
		"another close":        {sign(key, revocationJSON(map[string]any{"code": 1000})), ErrMalformed},
		"no tenant":            {sign(key, revocationJSON(map[string]any{"tenantId": nil})), ErrMalformed},
		"an unknown selector":  {sign(key, revocationJSON(map[string]any{"runId": "r"})), ErrMalformed},
		"an audience":          {sign(key, revocationJSON(map[string]any{"aud": "mwcc-node-01"})), ErrMalformed},
		"a grant":              {sign(key, grantJSON(nil)), ErrMalformed},
		"issued in the future": {sign(key, revocationJSON(map[string]any{"issuedAt": now + 5001})), ErrLifetime},
		"an unknown signer":    {sign(testKey("sandbox"), revocationJSON(nil)), ErrSignature},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := verifier.Revocation(test.token); !errors.Is(err, test.want) {
				t.Fatalf("got %v, want %v", err, test.want)
			}
		})
	}
	// A grant token is never taken as a revocation, nor the reverse.
	if _, err := verifier.Grant(sign(key, revocationJSON(nil))); !errors.Is(err, ErrMalformed) {
		t.Fatalf("revocation as grant: %v", err)
	}
}

func TestRevocationCoversOnlyGrantsIssuedAtOrBeforeIt(t *testing.T) {
	g := Grant{Binding: vectorBinding, IssuedAt: now, ExpiresAt: now + 60000, Scope: ScopeView}
	selector := Selector{TenantID: vectorBinding.TenantID, ViewID: vectorBinding.ViewID}
	if !(Revocation{Selector: selector, IssuedAt: now}).Covers(g) {
		t.Fatal("a revocation covers a grant issued at its instant")
	}
	if (Revocation{Selector: selector, IssuedAt: now - 1}).Covers(g) {
		t.Fatal("a revocation never covers access proven after it")
	}
	for _, other := range []Selector{
		{TenantID: "85086ad0-dab6-4cab-a0dc-6d029be8be76"},
		{TenantID: vectorBinding.TenantID, UserID: "11111111-2222-4333-8444-555555555556"},
		{TenantID: vectorBinding.TenantID, NativeViewID: strings.Repeat("b", 64)},
		{TenantID: vectorBinding.TenantID, ViewerID: "baaaaabb-cccc-4ddd-8eee-ffff00000302"},
	} {
		if (Revocation{Selector: other, IssuedAt: now}).Covers(g) {
			t.Fatalf("%+v covers another session", other)
		}
	}
}

func TestAuthorityIsASetWhoseOrderNeverMatters(t *testing.T) {
	view := func(issued, expires int64) Grant {
		return Grant{Binding: vectorBinding, IssuedAt: issued, ExpiresAt: expires, Scope: ScopeView}
	}
	control := func(issued, expires int64, controller string) Grant {
		g := view(issued, expires)
		g.Scope, g.ControllerID = ScopeControl, controller
		return g
	}
	const first, second = "3f1c2b4a-5d6e-4f70-8a9b-0c1d2e3f4a5b", "4f1c2b4a-5d6e-4f70-8a9b-0c1d2e3f4a5b"
	grants := []Grant{view(0, 60000), control(10000, 25000, first), view(20000, 80000), control(15000, 70000, second)}
	for _, order := range [][]int{{0, 1, 2, 3}, {0, 3, 2, 1}, {0, 2, 1, 3}} {
		a := NewAuthority(grants[order[0]])
		for _, index := range order[1:] {
			if err := a.Add(grants[index], 21000); err != nil {
				t.Fatal(err)
			}
		}
		if until, ok := a.ViewUntil(21000); !ok || until != 80000 {
			t.Fatalf("order %v: view until %d %v", order, until, ok)
		}
		if g, ok := a.Control(21000); !ok || g.ControllerID != second {
			t.Fatalf("order %v: control %+v %v", order, g, ok)
		}
		// The newest control grant expires; control lapses, viewing does not.
		if _, ok := a.Control(70000); ok {
			t.Fatalf("order %v: control after its grant expired", order)
		}
		if _, ok := a.ViewUntil(79999); !ok {
			t.Fatalf("order %v: viewing lapsed early", order)
		}
	}
	a := NewAuthority(view(0, 60000))
	foreign := view(1000, 61000)
	foreign.ViewerID = "baaaaabb-cccc-4ddd-8eee-ffff00000302"
	if err := a.Add(foreign, 2000); !errors.Is(err, ErrBinding) {
		t.Fatalf("foreign binding: %v", err)
	}
	if err := a.Add(view(1000, 1500), 2000); err != nil {
		t.Fatal(err)
	}
	if _, ok := a.Newest(); !ok {
		t.Fatal("the admitting grant is held")
	}
	// A revocation removes what it covers; access proven after it stays.
	a = NewAuthority(view(0, 60000))
	_ = a.Add(control(20000, 60000, first), 20000)
	selector := Selector{TenantID: vectorBinding.TenantID}
	if !a.Revoke(Revocation{Selector: selector, IssuedAt: 10000, Code: 4403}) {
		t.Fatal("the control grant was issued after the revocation")
	}
	if _, ok := a.Control(20001); !ok {
		t.Fatal("control proven after the revocation stays")
	}
	if a.Revoke(Revocation{Selector: selector, IssuedAt: 20000, Code: 4403}) {
		t.Fatal("nothing remains")
	}
	if _, ok := a.ViewUntil(20001); ok {
		t.Fatal("no view after every grant is revoked")
	}
}

func TestControlAuthorityNeverReturnsToAnOlderController(t *testing.T) {
	older := Grant{Binding: vectorBinding, Scope: ScopeControl, ControllerID: "3f1c2b4a-5d6e-4f70-8a9b-0c1d2e3f4a5b", IssuedAt: 1000, ExpiresAt: 60000}
	newer := older
	newer.ControllerID, newer.IssuedAt, newer.ExpiresAt = "4f1c2b4a-5d6e-4f70-8a9b-0c1d2e3f4a5b", 2000, 5000
	for _, order := range [][]Grant{{older, newer}, {newer, older}} {
		a := NewAuthority(order[0])
		if err := a.Add(order[1], 3000); err != nil {
			t.Fatal(err)
		}
		if g, ok := a.Control(4999); !ok || g.ControllerID != newer.ControllerID {
			t.Fatalf("newest controller before expiry: %+v %v", g, ok)
		}
		if g, ok := a.Control(5000); ok {
			t.Fatalf("expired newest grant restored old control: %+v", g)
		}
		a.Prune(5000)
		// Replaying a still-valid older grant cannot restore custody after
		// pruning the newest one; viewing may continue on that grant.
		if err := a.Add(older, 5001); err != nil {
			t.Fatal(err)
		}
		if g, ok := a.Control(5001); ok {
			t.Fatalf("replayed older grant restored old control: %+v", g)
		}
		if _, ok := a.ViewUntil(5001); !ok {
			t.Fatal("control expiry must not end valid viewing authority")
		}
		fresh := newer
		fresh.IssuedAt, fresh.ExpiresAt = 6000, 10000
		if err := a.Add(fresh, 6000); err != nil {
			t.Fatal(err)
		}
		if g, ok := a.Control(6000); !ok || g != fresh {
			t.Fatalf("freshly proven controller was not admitted: %+v %v", g, ok)
		}
	}
}

func TestRepeatedGrantDoesNotGrowAuthority(t *testing.T) {
	g := Grant{Binding: vectorBinding, Scope: ScopeView, IssuedAt: 1000, ExpiresAt: 60000}
	a := NewAuthority(g)
	for range 10000 {
		if err := a.Add(g, 2000); err != nil {
			t.Fatal(err)
		}
	}
	if len(a.grants) != 1 {
		t.Fatalf("repeated grant retained %d copies", len(a.grants))
	}
}

func TestTiedControllersStayAmbiguousUntilALaterProof(t *testing.T) {
	first := Grant{Binding: vectorBinding, Scope: ScopeControl, ControllerID: "3f1c2b4a-5d6e-4f70-8a9b-0c1d2e3f4a5b", IssuedAt: 1000, ExpiresAt: 60000}
	second := first
	second.ControllerID, second.ExpiresAt = "4f1c2b4a-5d6e-4f70-8a9b-0c1d2e3f4a5b", 5000
	for _, order := range [][]Grant{{first, second}, {second, first}} {
		a := NewAuthority(order[0])
		_ = a.Add(order[1], 2000)
		if _, ok := a.Control(2000); ok {
			t.Fatal("arrival order chose a tied controller")
		}
		a.Prune(5000)
		_ = a.Add(first, 5001)
		if _, ok := a.Control(5001); ok {
			t.Fatal("expiry/pruning/replay resolved an ambiguous controller")
		}
		if _, ok := a.ViewUntil(5001); !ok {
			t.Fatal("ambiguous control ended viewing")
		}
		fresh := second
		fresh.IssuedAt, fresh.ExpiresAt = 6000, 10000
		_ = a.Add(fresh, 6000)
		if g, ok := a.Control(6000); !ok || g.ControllerID != second.ControllerID {
			t.Fatal("a later proof did not restore unambiguous control")
		}
	}
}

func TestPublicKeyFiles(t *testing.T) {
	block := func(key ed25519.PrivateKey) string {
		der, _ := x509.MarshalPKIXPublicKey(key.Public())
		return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	}
	keys, err := ParsePublicKeys([]byte("\n" + block(testKey("a")) + block(testKey("b")) + "\n"))
	if err != nil || len(keys) != 2 {
		t.Fatalf("%d keys, %v", len(keys), err)
	}
	ecdsaKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&ecdsaKey.PublicKey)
	for name, content := range map[string]string{
		"empty":          "",
		"not PEM":        "ssh-ed25519 AAAA",
		"a private key":  string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1}})),
		"an ECDSA key":   string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})),
		"trailing text":  block(testKey("a")) + "junk",
		"a broken block": "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n",
	} {
		if _, err := ParsePublicKeys([]byte(content)); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	var ring KeyRing
	if len(ring.PublicKeys()) != 0 || ring.Apply([]byte("junk")) == nil || len(ring.PublicKeys()) != 0 {
		t.Fatal("an empty ring admits nothing")
	}
	if ring.Apply([]byte(block(testKey("a")))) != nil || ring.Apply([]byte("junk")) == nil || len(ring.PublicKeys()) != 1 {
		t.Fatal("a failed apply keeps the keys in force")
	}
}
