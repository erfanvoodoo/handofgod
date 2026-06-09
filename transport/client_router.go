package transport

import (
	"sync"

	"github.com/handofgod/frame"
	"github.com/handofgod/path"
)

// client_router.go is the client-side mirror of ServerManager: it lets a single
// wire.Client carry many concurrent sessions by routing each inbound downstream
// datagram to the right Session by the session id in its cleartext header.
//
// Usage: build one wire.Client, point its inbound at the router
// (wcli.SetInbound(router.Inbound)), and register each session returned by Dial
// under its assigned id.

// ClientRouter dispatches downstream datagrams to per-session Sessions by id.
// Safe for concurrent use.
type ClientRouter struct {
	mu       sync.RWMutex
	sessions map[uint16]*Session
}

// NewClientRouter creates an empty client-side router.
func NewClientRouter() *ClientRouter {
	return &ClientRouter{sessions: make(map[uint16]*Session)}
}

// Register adds (or replaces) the session for a session id.
func (r *ClientRouter) Register(sessionID uint16, s *Session) {
	r.mu.Lock()
	r.sessions[sessionID] = s
	r.mu.Unlock()
}

// Remove drops a session id (e.g. after Close).
func (r *ClientRouter) Remove(sessionID uint16) {
	r.mu.Lock()
	delete(r.sessions, sessionID)
	r.mu.Unlock()
}

// Get returns the session for an id, or nil.
func (r *ClientRouter) Get(sessionID uint16) *Session {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.sessions[sessionID]
}

// Count returns the number of registered sessions.
func (r *ClientRouter) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.sessions)
}

// Inbound routes one downstream datagram to the session named by its cleartext
// header id. It satisfies wire.Client's Inbound. Datagrams for unknown sessions
// (or that are too short to parse) are dropped — the AEAD still binds each
// datagram to its session's keys, so a misrouted id would fail to decrypt anyway.
func (r *ClientRouter) Inbound(datagram []byte, via *path.Path) {
	sid, _, err := frame.ParseDatagramHeader(datagram)
	if err != nil {
		return
	}
	if s := r.Get(sid); s != nil {
		_ = s.HandleInbound(datagram, via)
	}
}
