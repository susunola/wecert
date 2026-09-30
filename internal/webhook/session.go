package webhook

import (
	"strconv"
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
		// This endpoint is an oracle for whether a token is valid: GET reports
		// which credential matched and POST answers 200 vs 401. It therefore has
		// to count failed guesses exactly like /hook/* and /admin/*, or the
		// lockout there can be walked around from here.
		addr := clientIP(r)
		switch r.Method {
		case http.MethodGet:
			ok := s.tokenMatches(r) || s.adminTokenMatches(r)
			if !ok {
				if blocked, retryAfter := s.limiter.fail(addr, s.now()); blocked {
					w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())+1))
					writeJSON(w, http.StatusTooManyRequests,
						map[string]string{"error": "too many failed authentication attempts"})
					return
				}
			} else {
				s.limiter.recordSuccess(addr, s.now())
			}
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
				if blocked, retryAfter := s.limiter.fail(addr, s.now()); blocked {
					w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())+1))
					writeJSON(w, http.StatusTooManyRequests,
						map[string]string{"error": "too many failed authentication attempts"})
					return
				}
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "token rejected"})
				return
			}
			s.limiter.recordSuccess(addr, s.now())
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
					MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode,
					Secure:   r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https"),
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
		MaxAge:   int((7 * 24 * time.Hour).Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		// Behind a TLS terminator r.TLS is nil, so the raw token cookie would go
		// out unmarked and be sent over plain HTTP. Honour the standard header.
		Secure: r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https"),
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
