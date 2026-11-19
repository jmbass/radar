package auth

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/coreos/go-oidc/v3/oidc/oidctest"
	apierrors "k8s.io/apimachinery/pkg/api/errors"

	pkgauth "github.com/skyhook-io/radar/pkg/auth"
)

func TestStandaloneOIDCUserTokenSession(t *testing.T) {
	pkgauth.SetCredentialMode(pkgauth.CredentialsUserToken)
	t.Cleanup(func() { pkgauth.SetCredentialMode(pkgauth.CredentialsImpersonate) })
	idp := newFakeIDP(t, oidc.ES256)
	expires := time.Now().Add(15 * time.Minute).Truncate(time.Second)
	idp.claims = fmt.Sprintf(`{"iss":%q,"aud":"radar","email":"alice@example.com","sub":"alice","sid":"idp-session","groups":["idp-only"],"exp":%d}`, idp.issuer, expires.Unix())
	var reviewedToken string
	var reviewErr error
	h := idp.newHandler(t, Config{
		Secret: "session-secret", OIDCUsernamePrefix: "oidc:",
		TokenReviewer: func(_ context.Context, token string) (*User, error) {
			reviewedToken = token
			return &User{Username: "oidc:alice@example.com", Groups: []string{"k8s-dev", "system:authenticated"}}, reviewErr
		},
	})
	h.endSessionEndpoint = "https://idp.example.com/logout"
	h.SetRevoker(NewMemoryRevoker())

	var got *User
	protected := h.Authenticate(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got = UserFromContext(r.Context())
	}))
	request := func(cookies ...*http.Cookie) *httptest.ResponseRecorder {
		t.Helper()
		got = nil
		r := httptest.NewRequest(http.MethodGet, "/api/topology", nil)
		r.Header.Set(pkgauth.UserTokenHeader, "untrusted-header")
		for _, cookie := range cookies {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		protected.ServeHTTP(w, r)
		return w
	}
	login := func() *http.Cookie {
		t.Helper()
		w := runCallback(h)
		if w.Code != http.StatusFound {
			t.Fatalf("callback status = %d: %s", w.Code, w.Body.String())
		}
		if strings.Contains(strings.Join(w.Header().Values("Set-Cookie"), ";"), reviewedToken) {
			t.Fatal("callback wrote the Kubernetes credential to a cookie")
		}
		for _, c := range w.Result().Cookies() {
			if c.Name == oidcTokenSessionCookie {
				return c
			}
		}
		t.Fatal("no opaque session cookie")
		return nil
	}

	legacy := CreateSessionCookie(&User{Username: "oidc:alice@example.com"}, NewSessionID(), "", h.cfg.Secret, time.Hour, true)
	if w := request(legacy[0]); w.Code != http.StatusUnauthorized {
		t.Fatalf("legacy session and forwarded header were accepted: %d", w.Code)
	}
	old := login()
	cookie := login()
	if old.Value == cookie.Value || len(cookie.Value) != len(NewSessionID()) || !cookie.HttpOnly || !cookie.Secure || !cookie.Expires.Equal(expires) {
		t.Fatal("expected distinct opaque, secure session IDs limited to the token expiry")
	}
	if reviewedToken == "" || request(cookie).Code != http.StatusOK || got == nil || got.Token != reviewedToken || !slices.Equal(got.Groups, []string{"k8s-dev", "system:authenticated"}) {
		t.Fatal("request did not receive the reviewed ID token and Kubernetes groups")
	}

	r := httptest.NewRequest(http.MethodGet, "/auth/logout", nil)
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	h.HandleLogout(w, r)
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), "id_token_hint") || request(cookie).Code != http.StatusUnauthorized {
		t.Fatal("logout exposed the token or left the session usable")
	}

	h.tokenSessions.mu.Lock()
	entry := h.tokenSessions.entries[old.Value]
	entry.expires = time.Now().Add(-time.Second)
	h.tokenSessions.entries[old.Value] = entry
	h.tokenSessions.mu.Unlock()
	if request(old).Code != http.StatusUnauthorized {
		t.Fatal("expired server-side token session was accepted")
	}

	cookie = login()
	claims := fmt.Sprintf(`{"iss":%q,"aud":"radar","sub":"alice","sid":"idp-session","jti":"logout","exp":%d,"events":{"%s":{}}}`,
		idp.issuer, expires.Unix(), backchannelLogoutEventURI)
	token := oidctest.SignIDToken(idp.signer, idp.keyID, idp.alg, claims)
	r = httptest.NewRequest(http.MethodPost, "/auth/backchannel-logout", strings.NewReader(url.Values{"logout_token": {token}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	h.HandleBackchannelLogout(w, r)
	if w.Code != http.StatusOK || request(cookie).Code != http.StatusUnauthorized {
		t.Fatal("backchannel logout did not revoke the opaque session")
	}
	if _, ok := h.tokenSessions.get(cookie.Value); ok {
		t.Fatal("backchannel logout retained the token in memory")
	}

	reviewErr = apierrors.NewUnauthorized("wrong audience")
	if w := runCallback(h); w.Code != http.StatusForbidden || len(h.tokenSessions.entries) != 0 {
		t.Fatalf("Kubernetes-rejected token created a session: status %d", w.Code)
	}
}

func TestOIDCTokenSessionRemovesExpiredCredential(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sessions := &oidcTokenSessions{entries: make(map[string]oidcTokenSession)}
		sessions.add(oidcTokenSession{user: &User{Token: "token"}, expires: time.Now().Add(time.Minute)})
		time.Sleep(time.Minute)
		synctest.Wait()
		if len(sessions.entries) != 0 {
			t.Fatal("expired credential was retained in memory")
		}
	})
}
