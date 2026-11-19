package auth

import (
	"net/http"
	"sync"
	"time"
)

const oidcTokenSessionCookie = "__Host-radar_oidc_token_session"

type oidcTokenSession struct {
	user        *User
	providerSID string
	expires     time.Time
	timer       *time.Timer
}

// The browser's session cookie holds only a random local SID. The token and
// provider SID stay on the server, and the session cannot outlive the token.
type oidcTokenSessions struct {
	mu      sync.Mutex
	entries map[string]oidcTokenSession
}

func (s *oidcTokenSessions) add(entry oidcTokenSession) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.entries) >= 4096 {
		return ""
	}
	id := NewSessionID()
	entry.timer = time.AfterFunc(time.Until(entry.expires), func() { s.remove(id) })
	s.entries[id] = entry
	return id
}

func (s *oidcTokenSessions) get(id string) (oidcTokenSession, bool) {
	if s == nil || id == "" {
		return oidcTokenSession{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[id]
	if ok && !entry.expires.After(time.Now()) {
		s.removeLocked(id)
		return oidcTokenSession{}, false
	}
	return entry, ok
}

func oidcTokenSessionID(r *http.Request) string {
	c, err := r.Cookie(oidcTokenSessionCookie)
	if err != nil {
		return ""
	}
	return c.Value
}

func setOIDCTokenSessionCookie(w http.ResponseWriter, id string, expires time.Time) {
	c := &http.Cookie{
		Name: oidcTokenSessionCookie, Value: id, Expires: expires,
		Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	}
	if id == "" {
		c.MaxAge = -1
	}
	http.SetCookie(w, c)
}

func (s *oidcTokenSessions) remove(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.removeLocked(id)
}

func (s *oidcTokenSessions) revoke(providerSID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, entry := range s.entries {
		if entry.providerSID == providerSID {
			s.removeLocked(id)
		}
	}
}

func (s *oidcTokenSessions) removeLocked(id string) {
	if entry, ok := s.entries[id]; ok {
		entry.timer.Stop()
		delete(s.entries, id)
	}
}
