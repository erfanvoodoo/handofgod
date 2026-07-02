package main

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
)

// TestReadGreeting_OK covers the happy-path VER+NMETHODS+METHODS parse.
func TestReadGreeting_OK(t *testing.T) {
	buf := bytes.NewReader([]byte{0x05, 0x02, 0x00, 0x02})
	methods, err := readGreeting(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(methods, []byte{0x00, 0x02}) {
		t.Fatalf("methods = %v want [0x00, 0x02]", methods)
	}
}

// TestReadGreeting_BadVersion rejects non-5 versions.
func TestReadGreeting_BadVersion(t *testing.T) {
	buf := bytes.NewReader([]byte{0x04, 0x01, 0x00})
	if _, err := readGreeting(buf); err == nil {
		t.Fatal("expected error for VER=0x04")
	}
}

// TestReadGreeting_ShortRead: an EOF mid-methods must error, not silently
// short-return.
func TestReadGreeting_ShortRead(t *testing.T) {
	buf := bytes.NewReader([]byte{0x05, 0x03, 0x00, 0x02}) // says 3 methods, has 2
	_, err := readGreeting(buf)
	if err == nil {
		t.Fatal("expected error on short methods")
	}
	if err != io.ErrUnexpectedEOF {
		t.Logf("got %v (accepting any non-nil short-read err)", err)
	}
}

func TestChooseMethod(t *testing.T) {
	cases := []struct {
		offered []byte
		want    byte
	}{
		{[]byte{0x00}, methodNoAuth},
		{[]byte{0x02, 0x00}, methodNoAuth},       // no-auth accepted even if not first
		{[]byte{0x02, 0x01}, methodNoAcceptable}, // no supported method
		{[]byte{0xFF}, methodNoAcceptable},
	}
	for _, c := range cases {
		if got := chooseMethod(c.offered); got != c.want {
			t.Errorf("chooseMethod(%v) = 0x%02x want 0x%02x", c.offered, got, c.want)
		}
	}
}

// TestReadRequest_IPv4 parses a canonical CONNECT to 192.0.2.10:443.
func TestReadRequest_IPv4(t *testing.T) {
	packet := []byte{
		0x05, cmdConnect, 0x00, atypIPv4,
		192, 0, 2, 10,
		0x01, 0xBB, // 443
	}
	req, err := readRequest(bytes.NewReader(packet))
	if err != nil {
		t.Fatal(err)
	}
	if req.Cmd != cmdConnect || req.AddressType != atypIPv4 {
		t.Fatalf("unexpected req header: %+v", req)
	}
	if req.Address != "192.0.2.10:443" {
		t.Fatalf("Address = %q want 192.0.2.10:443", req.Address)
	}
	if req.Port != 443 {
		t.Fatalf("Port = %d want 443", req.Port)
	}
}

// TestReadRequest_Domain parses a domain-name target.
func TestReadRequest_Domain(t *testing.T) {
	host := "example.com"
	packet := []byte{0x05, cmdConnect, 0x00, atypDomain, byte(len(host))}
	packet = append(packet, []byte(host)...)
	packet = append(packet, 0x00, 0x50) // port 80
	req, err := readRequest(bytes.NewReader(packet))
	if err != nil {
		t.Fatal(err)
	}
	if req.Address != "example.com:80" {
		t.Fatalf("Address = %q want example.com:80", req.Address)
	}
	if req.AddressType != atypDomain {
		t.Fatalf("AddressType = 0x%02x want 0x%02x", req.AddressType, atypDomain)
	}
}

// TestReadRequest_IPv6 parses an IPv6 target.
func TestReadRequest_IPv6(t *testing.T) {
	addr := net.ParseIP("2001:db8::1").To16()
	packet := []byte{0x05, cmdConnect, 0x00, atypIPv6}
	packet = append(packet, addr...)
	packet = append(packet, 0x1F, 0x90) // port 8080
	req, err := readRequest(bytes.NewReader(packet))
	if err != nil {
		t.Fatal(err)
	}
	if req.AddressType != atypIPv6 {
		t.Fatalf("AddressType = 0x%02x want 0x%02x", req.AddressType, atypIPv6)
	}
	if req.Address != "[2001:db8::1]:8080" {
		t.Fatalf("Address = %q want [2001:db8::1]:8080", req.Address)
	}
}

// TestReadRequest_Domain_ZeroLength: a zero-length domain is malformed.
func TestReadRequest_Domain_ZeroLength(t *testing.T) {
	packet := []byte{0x05, cmdConnect, 0x00, atypDomain, 0x00, 0x00, 0x50}
	if _, err := readRequest(bytes.NewReader(packet)); err == nil {
		t.Fatal("expected error for zero-length domain")
	}
}

// TestReadRequest_UnsupportedATYP returns an error but still yields the
// partial request (so writeReply can echo the ATYP-not-supported REP code).
func TestReadRequest_UnsupportedATYP(t *testing.T) {
	packet := []byte{0x05, cmdConnect, 0x00, 0x99, 0x00}
	req, err := readRequest(bytes.NewReader(packet))
	if err == nil {
		t.Fatal("expected error for ATYP=0x99")
	}
	if req == nil || req.AddressType != 0x99 {
		t.Fatalf("expected partial req with ATYP=0x99, got %+v", req)
	}
}

// TestReadRequest_BadRSV rejects a non-zero reserved byte per RFC 1928.
func TestReadRequest_BadRSV(t *testing.T) {
	packet := []byte{0x05, cmdConnect, 0x01, atypIPv4, 1, 2, 3, 4, 0, 80}
	if _, err := readRequest(bytes.NewReader(packet)); err == nil {
		t.Fatal("expected error for RSV != 0")
	}
}

// TestReadRequest_UDPAssociateReturned parses BIND / UDP_ASSOCIATE so the
// caller can reply with commandNotSupported (rather than erroring here).
func TestReadRequest_UDPAssociateReturned(t *testing.T) {
	packet := []byte{0x05, cmdUDPAssociate, 0x00, atypIPv4, 1, 2, 3, 4, 0, 80}
	req, err := readRequest(bytes.NewReader(packet))
	if err != nil {
		t.Fatal(err)
	}
	if req.Cmd != cmdUDPAssociate {
		t.Fatalf("Cmd = 0x%02x want 0x%02x", req.Cmd, cmdUDPAssociate)
	}
}

// TestWriteMethodChoice writes the version + method byte.
func TestWriteMethodChoice(t *testing.T) {
	var buf bytes.Buffer
	if err := writeMethodChoice(&buf, methodNoAuth); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf.Bytes(), []byte{0x05, 0x00}) {
		t.Fatalf("wrote %v want [0x05, 0x00]", buf.Bytes())
	}
}

// TestWriteReply_IPv4 echoes the request's address in the reply.
func TestWriteReply_IPv4(t *testing.T) {
	req := &socksRequest{
		Cmd:         cmdConnect,
		AddressType: atypIPv4,
		RawAddress:  []byte{192, 0, 2, 10},
		Port:        443,
	}
	var buf bytes.Buffer
	if err := writeReply(&buf, repSuccess, req); err != nil {
		t.Fatal(err)
	}
	want := []byte{0x05, repSuccess, 0x00, atypIPv4, 192, 0, 2, 10, 0x01, 0xBB}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("wrote %v want %v", buf.Bytes(), want)
	}
}

// TestWriteReply_Domain includes the length prefix.
func TestWriteReply_Domain(t *testing.T) {
	host := "example.com"
	req := &socksRequest{
		Cmd:         cmdConnect,
		AddressType: atypDomain,
		RawAddress:  []byte(host),
		Port:        80,
	}
	var buf bytes.Buffer
	if err := writeReply(&buf, repSuccess, req); err != nil {
		t.Fatal(err)
	}
	if buf.Len() < 4+1+len(host)+2 {
		t.Fatalf("reply too short: %d bytes", buf.Len())
	}
	if buf.Bytes()[4] != byte(len(host)) {
		t.Fatalf("domain length byte = %d want %d", buf.Bytes()[4], len(host))
	}
	if !bytes.Equal(buf.Bytes()[5:5+len(host)], []byte(host)) {
		t.Fatalf("domain bytes mismatch: %q", buf.Bytes()[5:5+len(host)])
	}
	gotPort := binary.BigEndian.Uint16(buf.Bytes()[5+len(host):])
	if gotPort != 80 {
		t.Fatalf("port = %d want 80", gotPort)
	}
}

// TestWriteReply_NilRequest handles the error-before-request case.
func TestWriteReply_NilRequest(t *testing.T) {
	var buf bytes.Buffer
	if err := writeReply(&buf, repGeneralFailure, nil); err != nil {
		t.Fatal(err)
	}
	want := []byte{0x05, repGeneralFailure, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("wrote %v want %v", buf.Bytes(), want)
	}
}

// TestReplyCodeFor classifies dial errors into REP codes.
func TestReplyCodeFor(t *testing.T) {
	cases := []struct {
		in   string
		want byte
	}{
		{"destination not allowed", repConnectionNotAllowed},
		{"dial tcp 1.2.3.4:80: connect: connection refused", repConnectionRefused},
		{"lookup nx.example: no such host", repHostUnreachable},
		{"dial tcp: network is unreachable", repNetworkUnreachable},
		{"i/o timeout", repTTLExpired},
		{"invalid host:port", repAddressTypeNotSupport},
		{"something else entirely", repGeneralFailure},
	}
	for _, c := range cases {
		if got := replyCodeFor(c.in); got != c.want {
			t.Errorf("replyCodeFor(%q) = 0x%02x want 0x%02x", c.in, got, c.want)
		}
	}
}
