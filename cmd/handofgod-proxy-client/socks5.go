package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
)

// SOCKS5 protocol per RFC 1928. We implement only:
//   - Method 0x00 NO AUTHENTICATION REQUIRED
//   - CMD  0x01 CONNECT
// Everything else (BIND, UDP ASSOCIATE, username/password auth) is rejected.

const (
	socksVersion = 0x05

	methodNoAuth       byte = 0x00
	methodNoAcceptable byte = 0xFF

	cmdConnect      byte = 0x01
	cmdBind         byte = 0x02
	cmdUDPAssociate byte = 0x03

	atypIPv4   byte = 0x01
	atypDomain byte = 0x03
	atypIPv6   byte = 0x04

	repSuccess               byte = 0x00
	repGeneralFailure        byte = 0x01
	repConnectionNotAllowed  byte = 0x02
	repNetworkUnreachable    byte = 0x03
	repHostUnreachable       byte = 0x04
	repConnectionRefused     byte = 0x05
	repTTLExpired            byte = 0x06
	repCommandNotSupported   byte = 0x07
	repAddressTypeNotSupport byte = 0x08
)

// errUnsupportedVersion is returned by the reader when a peer sends a version
// byte other than 0x05.
var errUnsupportedVersion = errors.New("socks5: unsupported version")

// readGreeting consumes the client greeting (VER + NMETHODS + METHODS) and
// returns the offered method bytes.
func readGreeting(r io.Reader) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	if hdr[0] != socksVersion {
		return nil, fmt.Errorf("%w: got 0x%02x", errUnsupportedVersion, hdr[0])
	}
	n := int(hdr[1])
	if n == 0 {
		return nil, errors.New("socks5: NMETHODS = 0")
	}
	methods := make([]byte, n)
	if _, err := io.ReadFull(r, methods); err != nil {
		return nil, err
	}
	return methods, nil
}

// writeMethodChoice writes the server's chosen authentication method.
func writeMethodChoice(w io.Writer, method byte) error {
	_, err := w.Write([]byte{socksVersion, method})
	return err
}

// chooseMethod picks the first supported method from the offered list, or
// 0xFF if none is acceptable.
func chooseMethod(offered []byte) byte {
	for _, m := range offered {
		if m == methodNoAuth {
			return methodNoAuth
		}
	}
	return methodNoAcceptable
}

// socksRequest is a parsed CONNECT request. Address is always in the form
// "host:port" ready for net.Dial, whether the ATYP was IPv4, IPv6, or domain.
type socksRequest struct {
	Cmd     byte
	Address string
	// AddressType, RawAddress, and Port are preserved so writeReply can echo
	// them back verbatim (a well-behaved SOCKS server does this on success).
	AddressType byte
	RawAddress  []byte
	Port        uint16
}

// readRequest consumes the SOCKS5 request (VER CMD RSV ATYP DST.ADDR DST.PORT).
// It returns the parsed request; a non-CONNECT command is returned as-is so the
// caller can decide the reply code.
func readRequest(r io.Reader) (*socksRequest, error) {
	var hdr [4]byte // VER CMD RSV ATYP
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	if hdr[0] != socksVersion {
		return nil, fmt.Errorf("%w: got 0x%02x", errUnsupportedVersion, hdr[0])
	}
	if hdr[2] != 0x00 {
		return nil, fmt.Errorf("socks5: RSV != 0 (got 0x%02x)", hdr[2])
	}

	req := &socksRequest{Cmd: hdr[1], AddressType: hdr[3]}
	var hostPart string
	switch hdr[3] {
	case atypIPv4:
		buf := make([]byte, 4)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		req.RawAddress = buf
		hostPart = net.IP(buf).String()
	case atypIPv6:
		buf := make([]byte, 16)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		req.RawAddress = buf
		hostPart = net.IP(buf).String()
	case atypDomain:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return nil, err
		}
		if l[0] == 0 {
			return nil, errors.New("socks5: domain length = 0")
		}
		buf := make([]byte, int(l[0]))
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		req.RawAddress = buf
		hostPart = string(buf)
	default:
		return req, fmt.Errorf("socks5: unsupported ATYP 0x%02x", hdr[3])
	}

	var portBuf [2]byte
	if _, err := io.ReadFull(r, portBuf[:]); err != nil {
		return nil, err
	}
	req.Port = binary.BigEndian.Uint16(portBuf[:])
	req.Address = net.JoinHostPort(hostPart, strconv.Itoa(int(req.Port)))
	return req, nil
}

// writeReply writes a SOCKS5 reply with the given REP code, echoing the
// request's ATYP + address + port. Per RFC 1928 the BND.ADDR/BND.PORT fields
// are the address the server bound to; for a CONNECT via a forwarding tunnel
// we don't have a locally-bound address that means anything to the client, so
// we echo the destination (a common, well-behaved pattern).
func writeReply(w io.Writer, rep byte, req *socksRequest) error {
	buf := []byte{socksVersion, rep, 0x00}
	if req == nil {
		// No request to echo; return a zeroed IPv4 address.
		buf = append(buf, atypIPv4, 0, 0, 0, 0, 0, 0)
		_, err := w.Write(buf)
		return err
	}
	buf = append(buf, req.AddressType)
	switch req.AddressType {
	case atypDomain:
		buf = append(buf, byte(len(req.RawAddress)))
		buf = append(buf, req.RawAddress...)
	default:
		buf = append(buf, req.RawAddress...)
	}
	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], req.Port)
	buf = append(buf, portBuf[:]...)
	_, err := w.Write(buf)
	return err
}

// replyCodeFor maps a dial error message from the proxy-server (which comes
// through as an opaque string in the CONNECT-ERR payload) to a SOCKS5 REP
// code. It is a best-effort classification.
func replyCodeFor(reason string) byte {
	switch {
	case containsAny(reason, "not allowed", "disallowed"):
		return repConnectionNotAllowed
	case containsAny(reason, "refused"):
		return repConnectionRefused
	case containsAny(reason, "no such host", "no route"):
		return repHostUnreachable
	case containsAny(reason, "network is unreachable"):
		return repNetworkUnreachable
	case containsAny(reason, "timeout", "timed out"):
		return repTTLExpired
	case containsAny(reason, "invalid"):
		return repAddressTypeNotSupport
	default:
		return repGeneralFailure
	}
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(sub) == 0 {
			continue
		}
		if indexOf(s, sub) >= 0 {
			return true
		}
	}
	return false
}

// indexOf is a tiny substring finder that avoids importing strings just for
// this one use in a hot path. Case-sensitive.
func indexOf(s, sub string) int {
	if len(sub) == 0 {
		return 0
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
