package transport

import (
	"sync"
	"time"
)

// server_manager.go lets one authoritative server host many concurrent sessions.
// wire.Server decodes the session id from each query name and hands it to the
// Handler; ServerManager.HandleUpstream uses that id to dispatch to the matching
// ServerSession, so sessions are isolated even though they share a listener.
//
// Session establishment (the NK handshake that mints a session id + keys) is not
// performed here — sessions are Register'd once established. Wiring the handshake
// over DNS so the server can mint and Register sessions on demand is the Phase 4
// follow-up; the AEAD already binds each datagram to its session's keys, so a
// mis-routed or forged id simply fails to decrypt and is dropped.

// ServerManager routes inbound datagrams to per-session ServerSessions by session
// id. Safe for concurrent use (miekg dispatches each query on its own goroutine).
type ServerManager struct {
	mu       sync.RWMutex
	sessions map[uint16]*ServerSession
}

// NewServerManager creates an empty session router.
func NewServerManager() *ServerManager {
	return &ServerManager{sessions: make(map[uint16]*ServerSession)}
}

// Register adds (or replaces) the session served for a session id.
func (m *ServerManager) Register(sessionID uint16, s *ServerSession) {
	m.mu.Lock()
	m.sessions[sessionID] = s
	m.mu.Unlock()
}

// Remove drops a session id (e.g. on session close/timeout).
func (m *ServerManager) Remove(sessionID uint16) {
	m.mu.Lock()
	delete(m.sessions, sessionID)
	m.mu.Unlock()
}

// Get returns the session registered for a session id, or nil.
func (m *ServerManager) Get(sessionID uint16) *ServerSession {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.sessions[sessionID]
}

// Count returns the number of registered sessions.
func (m *ServerManager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sessions)
}

// Reap evicts and stops every session idle longer than idle, returning the count
// removed. This is the backstop for clients that vanish without a SESSION_CLOSE
// (which the server can't reliably receive over pull-based DNS).
func (m *ServerManager) Reap(idle time.Duration) int {
	m.mu.Lock()
	var dead []*ServerSession
	for sid, s := range m.sessions {
		if s.IdleFor() > idle {
			dead = append(dead, s)
			delete(m.sessions, sid)
		}
	}
	m.mu.Unlock()

	for _, s := range dead {
		s.Close() // stop its Run loop; done outside the lock
	}
	return len(dead)
}

// HandleUpstream routes one decoded upstream datagram to the session named by
// sessionID and returns that session's downstream datagram. An unknown session
// id returns nil, which makes wire.Server fall back to a cover response — so
// stray queries and cover traffic (which carry random ids) never touch a real
// session. It satisfies wire.UpstreamFunc.
func (m *ServerManager) HandleUpstream(datagram []byte, sessionID uint16) []byte {
	s := m.Get(sessionID)
	if s == nil {
		return nil
	}
	return s.HandleUpstream(datagram, sessionID)
}
