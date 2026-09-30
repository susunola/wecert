package webhook

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// Session cookies let the web console talk to the daemon on the same origin
// without holding the raw bearer tokens in JavaScript. The cookie values ARE
// the tokens, but HttpOnly, so XSS cannot read them; they are only sent to
// this daemon (Path=/, SameSite=Lax). Issued once via POST /api/session.
const (
	cookieRead  = "wecert_read"
	cookieAdmin = "wecert_admin"
)

func (s *Server) handleSession() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			writeJSON(w, http.StatusOK, map[string]any{
				"read":  s.tokenMatches(r),
				"admin": s.adminTokenMatches(r),
			})
		case http.MethodPost:
			var body struct {
				Token     string `json:"token"`
				AdminToken string `json:"adminToken"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "body must be JSON"})
				return
			}
			s.tokenMu.RLock()
			wantRead, wantAdmin := s.token, s.adminToken
			s.tokenMu.RUnlock()
			okRead := false
			okAdmin := false
			if body.Token != "" && wantRead != "" &&
				subtle.ConstantTimeCompare([]byte(body.Token), []byte(wantRead)) == 1 {
				okRead = true
			}
			if body.AdminToken != "" && wantAdmin != "" &&
				subtle.ConstantTimeCompare([]byte(body.AdminToken), []byte(wantAdmin)) == 1 {
				okAdmin = true
			}
			// Accept the admin token as a read credential too: one paste is enough
			// when the console holds both.
			if !okRead && okAdmin && wantRead != "" &&
				subtle.ConstantTimeCompare([]byte(body.AdminToken), []byte(wantRead)) == 1 {
				okRead = true
			}
			if !okRead && !okAdmin {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "token rejected"})
				return
			}
			if okRead {
				tok := body.Token
				if tok == "" {
					// Only the admin token was presented and it doubles as the read token.
					tok = body.AdminToken
				}
				http.SetCookie(w, sessionCookie(cookieRead, tok, r))
			}
			if okAdmin {
				tok := body.AdminToken
				if tok == "" {
					tok = body.Token
				}
				http.SetCookie(w, sessionCookie(cookieAdmin, tok, r))
			}
			writeJSON(w, http.StatusOK, map[string]any{"read": okRead, "admin": okAdmin})
		case http.MethodDelete:
			for _, name := range []string{cookieRead, cookieAdmin} {
				http.SetCookie(w, &http.Cookie{
					Name: name, Value: "", Path: "/",
					MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: r.TLS != nil,
				})
			}
			writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		default:
			w.Header().Set("Allow", "GET, POST, DELETE")
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "use GET, POST or DELETE"})
		}
	}
}

func sessionCookie(name, value string, r *http.Request) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   int((30 * 24 * time.Hour).Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
	}
}

// presentedToken returns the bearer/header token, or the matching session cookie.
func presentedToken(r *http.Request, cookieName string) string {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	if c, err := r.Cookie(cookieName); err == nil && c.Value != "" {
		return c.Value
	}
	return ""
}
