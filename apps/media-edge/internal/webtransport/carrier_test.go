// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package webtransport

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/daytonaio/media-edge/internal/view"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	wt "github.com/quic-go/webtransport-go"
)

// pair exercises the actual HTTP/3 CONNECT and QUIC flow control. Its TLS key
// is generated in memory for this test and never stored or printed.
func pair(t *testing.T, action func(*carrier)) (*wt.Session, *wt.Stream, context.Context, string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("test certificate: version=%d validity=%s algorithm=%s", parsed.Version, parsed.NotAfter.Sub(parsed.NotBefore), parsed.PublicKeyAlgorithm)
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	server := &wt.Server{H3: http3.Server{TLSConfig: &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}, QUICConfig: &quic.Config{EnableDatagrams: true}}, CheckOrigin: func(*http.Request) bool { return true }}
	server.H3.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, err := server.Upgrade(w, r)
		if err != nil {
			t.Error(err)
			return
		}
		c, err := newCarrier(s)
		if err != nil {
			t.Error(err)
			return
		}
		action(c)
		<-s.Context().Done()
	})
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	dialer := &wt.Dialer{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // task-scoped test certificate
		QUICConfig:      &quic.Config{EnableDatagrams: true, InitialStreamReceiveWindow: 32 << 10, MaxStreamReceiveWindow: 32 << 10, InitialConnectionReceiveWindow: 4 << 20, MaxConnectionReceiveWindow: 4 << 20},
	}
	t.Cleanup(func() { _ = dialer.Close() })
	_, s, err := dialer.Dial(ctx, "https://"+listener.LocalAddr().String()+"/v1/channel", nil)
	if err != nil {
		t.Fatal(err)
	}
	control, err := s.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = control.SetDeadline(time.Now().Add(5 * time.Second))
	magic := make([]byte, len(Magic))
	if _, err := io.ReadFull(control, magic); err != nil || string(magic) != Magic {
		t.Fatalf("control magic %q: %v", magic, err)
	}
	hash := sha256.Sum256(der)
	return s, control, ctx, "https://" + listener.LocalAddr().String() + "/v1/channel", base64.StdEncoding.EncodeToString(hash[:])
}

func record(t *testing.T, stream io.Reader) string {
	t.Helper()
	var prefix [4]byte
	if _, err := io.ReadFull(stream, prefix[:]); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, binary.BigEndian.Uint32(prefix[:]))
	if _, err := io.ReadFull(stream, data); err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestAPictureWhoseReaderStopsCannotHoldControlOrAudio(t *testing.T) {
	payload := bytes.Repeat([]byte{37}, 2<<20)
	s, control, ctx, _, _ := pair(t, func(c *carrier) {
		for _, d := range []*view.Delivery{
			{Kind: view.Record, Text: []byte(`{"type":"status"}`)},
			{Kind: view.Video, Header: []byte(`{"track":"video"}`), Payload: payload},
			{Kind: view.Record, Text: []byte(`{"type":"cursor"}`)},
			{Kind: view.Audio, Header: []byte(`{"track":"audio"}`), Payload: []byte{1, 2, 3}},
		} {
			if err := c.Send(d); err != nil {
				t.Error(err)
				return
			}
		}
		if _, _, err := c.Receive(); err != nil {
			t.Error(err)
			return
		}
		if err := c.Send(&view.Delivery{Kind: view.Record, Text: []byte(`{"type":"control","ok":true}`)}); err != nil {
			t.Error(err)
		}
	})
	if got := record(t, control); got != `{"type":"status"}` {
		t.Fatal(got)
	}
	// The picture's reader has consumed zero bytes and its 32KiB window is
	// full. These unrelated lanes must still make progress before it drains.
	if got := record(t, control); got != `{"type":"cursor"}` {
		t.Fatal(got)
	}
	input := []byte(`{"type":"control","op":"input"}`)
	var inputPrefix [4]byte
	binary.BigEndian.PutUint32(inputPrefix[:], uint32(len(input)))
	if _, err := control.Write(append(inputPrefix[:], input...)); err != nil {
		t.Fatal(err)
	}
	if got := record(t, control); got != `{"type":"control","ok":true}` {
		t.Fatalf("input reply blocked by picture: %s", got)
	}
	packet, err := s.ReceiveDatagram(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint64(packet[:8]) != 2 || !bytes.Equal(packet[len(packet)-3:], []byte{1, 2, 3}) {
		t.Fatalf("audio packet %v", packet)
	}
	picture, err := s.AcceptUniStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = picture.SetReadDeadline(time.Now().Add(5 * time.Second))
	encoded, err := io.ReadAll(picture)
	if err != nil {
		t.Fatal(err)
	}
	if encoded[0] != 1 || binary.BigEndian.Uint64(encoded[1:9]) != 1 || binary.BigEndian.Uint64(encoded[9:17]) != 1 {
		t.Fatalf("picture prefix %v", encoded[:17])
	}
	if !bytes.Equal(encoded[len(encoded)-len(payload):], payload) {
		t.Fatal("picture changed")
	}
}

func TestViewerMessagesAreFramedAndBoundedBeforeAllocation(t *testing.T) {
	got := make(chan string, 1)
	s, control, ctx, _, _ := pair(t, func(c *carrier) {
		text, message, err := c.Receive()
		if err != nil || !text {
			t.Errorf("viewer message: %v", err)
			return
		}
		got <- string(message)
		_, _, err = c.Receive()
		if err == nil {
			t.Error("accepted an oversized message")
		}
	})
	message := []byte(`{"type":"presentation","width":400,"height":800}`)
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(message)))
	if _, err := control.Write(append(prefix[:], message...)); err != nil {
		t.Fatal(err)
	}
	select {
	case read := <-got:
		if read != string(message) {
			t.Fatal(read)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	binary.BigEndian.PutUint32(prefix[:], ^uint32(0))
	if _, err := control.Write(prefix[:]); err != nil {
		t.Fatal(err)
	}
	select {
	case <-s.Context().Done():
	case <-ctx.Done():
		t.Fatal("oversized input did not close the session")
	}
}
