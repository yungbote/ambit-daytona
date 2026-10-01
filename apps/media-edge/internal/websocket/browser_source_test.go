// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package websocket_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daytonaio/media-edge/internal/daytona"
	"github.com/daytonaio/media-edge/internal/grant"
	"github.com/daytonaio/media-edge/internal/session"
	"github.com/daytonaio/media-edge/internal/testlink"
	"github.com/daytonaio/media-edge/internal/view"
	edgews "github.com/daytonaio/media-edge/internal/websocket"
	edgewt "github.com/daytonaio/media-edge/internal/webtransport"
)

type receivedSource struct {
	session.Upstream
	onReceived func(uint64)
	onPicture  func(string, sourcePicture)
}

type sourcePicture struct {
	StreamID                                         string `json:"streamId"`
	Seq                                              uint64 `json:"seq"`
	BodyBytes, Parts, CanonicalBytes, WSFramingBytes uint64
	SHA256                                           string
}

func (u receivedSource) DialView(ctx context.Context, target session.Target, viewer string, declaration view.Declaration) (session.Conn, error) {
	conn, err := u.Upstream.DialView(ctx, target, viewer, declaration)
	if err != nil {
		return nil, err
	}
	return &receivedConnection{Conn: conn, onReceived: u.onReceived, onPicture: func(value sourcePicture) { u.onPicture(viewer, value) }}, nil
}

type receivedConnection struct {
	session.Conn
	onReceived func(uint64)
	onPicture  func(sourcePicture)
	picture    sourcePicture
	declared   uint64
	body       hash.Hash
}

// Hash the source's original envelopes immediately at the real T1 boundary.
// This observer retains a hash state and scalar counts, never another body.
func (c *receivedConnection) Read() (bool, []byte, error) {
	text, message, err := c.Conn.Read()
	if err != nil {
		fmt.Printf("source/T1 Read ended: %T %v\n", err, err)
	}
	if err != nil || text || len(message) < 4 {
		return text, message, err
	}
	size := int(binary.BigEndian.Uint32(message))
	if size <= 0 || size > len(message)-4 {
		return text, message, err
	}
	var header struct {
		Track, StreamID string
		Seq, ByteLength uint64
		Offset          *uint64
	}
	if json.Unmarshal(message[4:4+size], &header) != nil || header.Track != "video" || header.Offset == nil {
		return text, message, err
	}
	if *header.Offset == 0 {
		c.picture = sourcePicture{StreamID: header.StreamID, Seq: header.Seq}
		c.declared, c.body = header.ByteLength, sha256.New()
	}
	if c.body == nil || c.picture.StreamID != header.StreamID || c.picture.Seq != header.Seq || c.picture.BodyBytes != *header.Offset {
		fmt.Printf("SOURCE_OBSERVER_DISCONTIGUITY current=%s/%d/%d received=%s/%d/%d bodyPresent=%v\n", c.picture.StreamID, c.picture.Seq, c.picture.BodyBytes, header.StreamID, header.Seq, *header.Offset, c.body != nil)
		return false, nil, fmt.Errorf("source byte observer found a noncontiguous picture")
	}
	payload := message[4+size:]
	_, _ = c.body.Write(payload)
	c.picture.BodyBytes += uint64(len(payload))
	c.picture.Parts++
	c.picture.CanonicalBytes += uint64(len(message))
	framing := 2
	if len(message) > 125 {
		framing += 2
	}
	if len(message) > 65535 {
		framing += 6
	}
	c.picture.WSFramingBytes += uint64(len(message) + framing)
	if c.picture.BodyBytes == c.declared {
		c.picture.SHA256 = fmt.Sprintf("%x", c.body.Sum(nil))
		c.onPicture(c.picture)
		c.body = nil
	}
	return text, message, err
}

func (c *receivedConnection) RateInput() bool {
	input, ok := c.Conn.(session.RateUpstream)
	return ok && input.RateInput()
}

func (c *receivedConnection) Write(message []byte) error {
	if err := c.Conn.Write(message); err != nil {
		return err
	}
	var value struct {
		Type   string
		Offset uint64
	}
	if c.onReceived != nil && json.Unmarshal(message, &value) == nil && value.Type == "received" {
		c.onReceived(value.Offset)
	}
	return nil
}

// Native source lifecycle is owned outside this test. T1's task bridge owns
// discovery/custody; real T1 and edge paths and production browser consumers
// run here, without claiming Product authentication or live sandbox custody.
func TestExistingNativeSourceThroughT1EdgeAndBrowser(t *testing.T) {
	metadata, script, worker := os.Getenv("MEDIA_EDGE_BROWSER_T1_SOURCE_FILE"), os.Getenv("MEDIA_EDGE_BROWSER_CHUNKS_SCRIPT"), os.Getenv("MEDIA_EDGE_BROWSER_INTEROP_WORKER")
	if metadata == "" || script == "" || worker == "" {
		t.Skip("existing T1 harness metadata, production browser script and built worker required")
	}
	observePartial := os.Getenv("MEDIA_EDGE_BROWSER_AUDIO_OBSERVE_PARTIAL") == "1"
	data, err := os.ReadFile(metadata)
	if err != nil {
		t.Fatal(err)
	}
	var source struct{ BaseURL, SessionID, ViewID string }
	if err := json.Unmarshal(data, &source); err != nil {
		t.Fatal(err)
	}
	address, err := url.Parse(source.BaseURL)
	if err != nil || address.Hostname() != "127.0.0.1" {
		t.Fatal("T1 source fixture must be loopback")
	}
	proxy := httputil.NewSingleHostReverseProxy(address)
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.URL.Path = strings.TrimPrefix(r.URL.Path, "/sandbox-1")
		r.URL.RawPath = ""
		proxy.ServeHTTP(w, r)
	}))
	defer proxyServer.Close()
	grantServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		identity := r.URL.Query().Get("viewerId")
		if identity == "" {
			identity = viewerID
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"token": token(map[string]any{"sessionId": source.SessionID, "nativeViewId": source.ViewID, "viewerId": identity})})
	}))
	defer grantServer.Close()
	upstream, err := daytona.New(proxyServer.URL, "task-fixture.nosecret", "")
	if err != nil {
		t.Fatal(err)
	}
	e := &session.Edge{Verifier: grant.Verifier{Keys: staticKeys{signer.Public().(ed25519.PublicKey)}, Audience: "edge-a"},
		Hub: session.NewHub(nil), Upstream: upstream, Log: slog.New(slog.NewTextHandler(os.Stdout, nil))}
	var receiptMu sync.Mutex
	receipts := make(map[string][]sourcePicture)
	onPicture := func(viewer string, picture sourcePicture) {
		receiptMu.Lock()
		receipts[viewer] = append(receipts[viewer], picture)
		receiptMu.Unlock()
		t.Logf("actual T1 source bytes viewer%s: %+v", viewer, picture)
	}
	e.Upstream = receivedSource{Upstream: upstream, onPicture: onPicture}
	wsServer := httptest.NewUnstartedServer(edgews.NewHandler(e))
	fullSlow := os.Getenv("MEDIA_EDGE_BROWSER_NATIVE_FULL_SLOW") == "1"
	fullSlowQUIC := os.Getenv("MEDIA_EDGE_BROWSER_NATIVE_FULL_SLOW_QUIC") == "1"
	audioSteady := observePartial && os.Getenv("MEDIA_EDGE_BROWSER_AUDIO_STEADY") == "1"
	ratePhase := os.Getenv("MEDIA_EDGE_BROWSER_NATIVE_RATE_PHASE") == "1" || fullSlow
	quicRatePhase := os.Getenv("MEDIA_EDGE_BROWSER_NATIVE_QUIC_RATE_PHASE") == "1" || fullSlowQUIC
	if ratePhase {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		var changeRate func(int64)
		var bytes func() int64
		var writeTrace func() edgews.PacedTrace
		wsServer.Listener, changeRate, bytes, writeTrace = edgews.PaceBrowserTestListener(wsServer.Listener, ctx)
		defer func() {
			trace, err := json.Marshal(writeTrace())
			if err != nil {
				t.Error(err)
			} else {
				t.Logf("TASK_WIRE_WRITES:%s", trace)
			}
		}()
		if audioSteady {
			changeRate(100000000)
		} else {
			changeRate(500000)
		}
		prefixes := 0
		e.Upstream = receivedSource{Upstream: upstream, onPicture: onPicture, onReceived: func(offset uint64) {
			prefixes++
			if fullSlow {
				if audioSteady && prefixes == 32 {
					changeRate(500000)
					t.Logf("steady audio: fast bootstrap ended at validated prefix32/offset%d; physical TCP now500k", offset)
				}
				if prefixes == 32 || prefixes == 64 || prefixes == 128 || prefixes%1024 == 0 {
					t.Logf("full fixed500k consumer prefix%d/offset%d: serialized%dB", prefixes, offset, bytes())
				}
				return
			}
			switch prefixes {
			case 32:
				t.Logf("actual consumer prefix%d/offset%d at500k: serialized%dB; physical drop250k", prefixes, offset, bytes())
				changeRate(250000)
			case 64:
				t.Logf("actual consumer prefix%d/offset%d after250k: serialized%dB; recovery500k", prefixes, offset, bytes())
				changeRate(500000)
			case 128:
				t.Logf("actual consumer prefix%d/offset%d after500k recovery: serialized%dB; release to100M", prefixes, offset, bytes())
				changeRate(100000000)
			}
		}}
	}
	wsServer.Start()
	defer wsServer.Close()
	wtServer := edgewt.NewServer(e)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	wtServer.H3.TLSConfig = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	defer wtServer.Close()
	go func() { _ = wtServer.Serve(listener) }()
	wtAddress := listener.LocalAddr()
	if quicRatePhase {
		var changeRate func(uint64)
		var bytes func() uint64
		bits := uint64(500000)
		if audioSteady {
			bits = 100000000
		}
		link := testlink.NewPacket(testlink.PacketConfig{Bits: bits, Queue: 60, Seed: 19})
		wtAddress = link.Path(t, wtAddress)
		changeRate = link.SetBits
		bytes = func() uint64 { return link.Stats().Bytes }
		prefixes := 0
		e.Upstream = receivedSource{Upstream: upstream, onPicture: onPicture, onReceived: func(offset uint64) {
			prefixes++
			if fullSlowQUIC {
				if audioSteady && prefixes == 32 {
					changeRate(500000)
					t.Logf("steady audio: fast bootstrap ended at validated prefix32/offset%d; physical QUIC now500k", offset)
				}
				if prefixes == 32 || prefixes == 64 || prefixes == 128 || prefixes%1024 == 0 {
					t.Logf("full fixed500k QUIC consumer prefix%d/offset%d: serialized%dB", prefixes, offset, bytes())
				}
				return
			}
			switch prefixes {
			case 32:
				t.Logf("actual QUIC consumer prefix%d/offset%d at500k: serialized%dB; physical drop250k", prefixes, offset, bytes())
				changeRate(250000)
			case 64:
				t.Logf("actual QUIC consumer prefix%d/offset%d after250k: serialized%dB; recovery500k", prefixes, offset, bytes())
				changeRate(500000)
			case 128:
				t.Logf("actual QUIC consumer prefix%d/offset%d after500k recovery: serialized%dB; release to100M", prefixes, offset, bytes())
				changeRate(100000000)
			}
		}}
	}
	hash := sha256.Sum256(der)
	mixed := os.Getenv("MEDIA_EDGE_BROWSER_NATIVE_MIXED8") == "1"
	var readyMu sync.Mutex
	ready := 0
	run := func(t *testing.T) {
		carriers := []string{"websocket", "webtransport"}
		if mixed {
			carriers = []string{"websocket", "webtransport", "websocket", "webtransport", "websocket", "webtransport", "websocket", "webtransport"}
		}
		for index, carrier := range carriers {
			name := carrier
			identity := viewerID
			if mixed {
				name = fmt.Sprintf("%s-%d", carrier, index)
				identity = fmt.Sprintf("baaaaabb-cccc-4ddd-8eee-ffff000004%02d", index)
			}
			t.Run(name, func(t *testing.T) {
				if mixed {
					t.Parallel()
				}
				options := map[string]any{"tenantId": tenant, "viewerId": identity, "renewUrl": grantServer.URL,
					"token": token(map[string]any{"sessionId": source.SessionID, "nativeViewId": source.ViewID, "viewerId": identity})}
				timeout := 45 * time.Second
				if quicRatePhase {
					if carrier != "webtransport" {
						t.Skip("QUIC packet serializer qualifies WebTransport; TCP fixture is separate")
					}
					options["ratePhase"] = true
					options["timeoutMs"] = 180000
					timeout = 190 * time.Second
				}
				if ratePhase {
					if carrier != "websocket" {
						t.Skip("TCP rate serializer qualifies WebSocket; QUIC rate fixture is separate")
					}
					options["ratePhase"] = true
					options["timeoutMs"] = 180000
					timeout = 190 * time.Second
					if fullSlow {
						options["timeoutMs"] = 1200000
						timeout = 1210 * time.Second
					}
				}
				if os.Getenv("MEDIA_EDGE_BROWSER_NATIVE_CANCEL_PARTIAL") == "1" {
					options["cancelPartial"] = true
				}
				if os.Getenv("MEDIA_EDGE_BROWSER_NATIVE_STALL_PARTIAL") == "1" || mixed && index >= 6 {
					options["stallPartial"] = true
				}
				if observePartial {
					options["observePartial"] = true
					if os.Getenv("MEDIA_EDGE_BROWSER_AUDIO_CONTROLS") == "1" {
						options["audioControls"] = true
					}
					options["rateProfile"] = "fast"
					if fullSlow || fullSlowQUIC {
						options["rateProfile"] = "fixed-500k-cold"
					}
					if audioSteady {
						options["observeStartPrefix"] = 32
						options["rateProfile"] = "fast-bootstrap-then-500k-at-prefix32"
					}
					options["timeoutMs"] = 180000
					timeout = 190 * time.Second
				}
				if os.Getenv("MEDIA_EDGE_BROWSER_NATIVE_WIDE") == "1" {
					options["size"] = map[string]int{"width": 2048, "height": 2048}
					if !ratePhase && !quicRatePhase {
						options["timeoutMs"] = 90000
						timeout = 100 * time.Second
					}
				}
				inputPhase := os.Getenv("MEDIA_EDGE_BROWSER_NATIVE_INPUT") == "1"
				if markerPath := os.Getenv("MEDIA_EDGE_BROWSER_NATIVE_MARKER_FILE"); markerPath != "" {
					data, err := os.ReadFile(markerPath)
					if err != nil {
						t.Fatal(err)
					}
					var marker map[string]any
					if err := json.Unmarshal(data, &marker); err != nil {
						t.Fatal(err)
					}
					options["marker"] = marker
				}
				if reference := os.Getenv("MEDIA_EDGE_BROWSER_NATIVE_REFERENCE_FILE"); reference != "" {
					options["referenceImage"] = reference
					options["negativeReferenceImage"] = os.Getenv("MEDIA_EDGE_BROWSER_NATIVE_NEGATIVE_REFERENCE_FILE")
					options["referenceRegions"] = []map[string]any{
						{"name": "typed field", "left": 52, "top": 341, "width": 190, "height": 28},
						{"name": "counter", "left": 155, "top": 397, "width": 18, "height": 24},
					}
				}
				if inputPhase {
					prefix := os.Getenv("MEDIA_EDGE_BROWSER_INPUT_RECEIPT_PREFIX")
					if prefix == "" {
						t.Fatal("unique native owner input receipt prefix required")
					}
					options["actionsFile"] = prefix + "-" + carrier + ".json"
					if mixed {
						options["actionsFile"] = prefix + "-mixed.json"
						options["inputCarrier"] = "webtransport"
						options["expectedInput"] = "wt physical input"
					}
					options["timeoutMs"] = 180000
					timeout = 190 * time.Second
				}
				settings, _ := json.Marshal(options)
				settingsPath := filepath.Join(t.TempDir(), "settings.json")
				if err := os.WriteFile(settingsPath, settings, 0600); err != nil {
					t.Fatal(err)
				}
				endpoint := "ws" + strings.TrimPrefix(wsServer.URL, "http") + edgews.Path
				if carrier == "webtransport" {
					endpoint = "https://" + wtAddress.String() + edgewt.Path
				}
				ctx, cancel := context.WithTimeout(context.Background(), timeout)
				defer cancel()
				cmd := exec.CommandContext(ctx, "node", script, endpoint, "live", carrier, worker, base64.StdEncoding.EncodeToString(hash[:]))
				cmd.Env = append(os.Environ(), "MEDIA_EDGE_BROWSER_SETTINGS_FILE="+settingsPath)
				if prefix := os.Getenv("MEDIA_EDGE_BROWSER_SCREENSHOT_PREFIX"); prefix != "" {
					cmd.Env = append(cmd.Env, "MEDIA_EDGE_BROWSER_SCREENSHOT_FILE="+prefix+"-"+name+".png")
				}
				var err error
				var output []byte
				if inputPhase {
					stdout, openErr := cmd.StdoutPipe()
					if openErr != nil {
						t.Fatal(openErr)
					}
					cmd.Stderr = os.Stderr
					if err = cmd.Start(); err == nil {
						var capture bytes.Buffer
						scanner := bufio.NewScanner(stdout)
						for scanner.Scan() {
							line := scanner.Text()
							fmt.Println(line)
							capture.WriteString(line + "\n")
							if mixed && line == "NATIVE_INPUT_READY:"+carrier {
								readyMu.Lock()
								ready++
								if ready == 8 {
									if e.Hub.Len() != 8 {
										t.Error("mixed input did not retain all eight live attachments")
									} else {
										fmt.Println("NATIVE_MIXED_ALL_READY")
									}
								}
								readyMu.Unlock()
							}
						}
						err = cmd.Wait()
						if err == nil {
							err = scanner.Err()
						}
						output = capture.Bytes()
					}
				} else {
					output, err = cmd.CombinedOutput()
					t.Log(string(output))
				}
				if err == nil && !observePartial {
					lines := strings.Split(strings.TrimSpace(string(output)), "\n")
					var result struct {
						Hash        string
						DecodeBytes []uint64
						LastPaint   struct {
							StreamID string
							Seq      uint64
						}
					}
					if json.Unmarshal([]byte(lines[len(lines)-1]), &result) != nil {
						t.Fatal("consumer did not return its byte receipt")
					}
					receiptMu.Lock()
					matched := false
					for _, picture := range receipts[identity] {
						matched = matched || picture.StreamID == result.LastPaint.StreamID && picture.Seq == result.LastPaint.Seq && picture.SHA256 == result.Hash
					}
					receiptMu.Unlock()
					if !matched {
						t.Fatal("production consumer bytes did not match a complete source/T1 picture")
					}
				}
				if err != nil {
					t.Fatalf("actual T1/edge/%s native consumer: %v", carrier, err)
				}
			})
		}
	}
	if mixed {
		t.Run("mixed8", run)
	} else {
		run(t)
	}
	if !t.Failed() {
		if observePartial {
			t.Logf("observation complete with exact live T1 fixture %s/%s; interval and apparatus checks only, PCM continuity is not accepted by this gate", source.SessionID, source.ViewID)
		} else {
			t.Logf("source composition passed with exact live T1 fixture %s/%s; bridge forwarding, not Product auth", source.SessionID, source.ViewID)
		}
	}
}
