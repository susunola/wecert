package webhook

// The guarded /admin handlers are the only place this package can change something on disk,
// and most of their behaviour is what they do when they are NOT allowed to: the wrong method,
// an operation the process never wired, a body that cannot be read, a confirm token that is
// expired, spent, or bound to another source. The tests below drive each of those through the
// real http.Handler the package mounts, and read the audit file for the parts an operator only
// ever sees there.

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/susunola/wecert/internal/state"
)

// adminOpsServer builds the guarded surface with its audit sink and logger under the test's
// control. The audit writer is deliberately best effort -- a sink that cannot be written is
// logged and the request still succeeds -- so its failure paths are invisible from the
// response and have to be asserted against the log the operator would actually read.
func adminOpsServer(t *testing.T, ops AdminOps, auditPath string, logs *bytes.Buffer) *Server {
	t.Helper()
	rec := &fakeReconciler{names: []string{"a"}}
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if logs != nil {
		log = slog.New(slog.NewTextHandler(logs, nil))
	}
	s, err := NewWithAdmin(rec, store, testToken,
		AdminOptions{Token: adminTok, AuditPath: auditPath, Ops: ops},
		context.Background(), log)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestUnwiredAdminOpsAnswerNotFound walks the whole guarded surface with an empty AdminOps.
//
// The routes are mounted when the admin token is set, but the operations behind them are
// individually optional: a deployment that only wants backup-health must not expose restore,
// and "there is nothing here to do that" is a 404, not a 200 with an empty result and not a
// 500 from a nil call. The nil check also has to come before the body is read, so a
// well-formed request cannot reach an operation that was never wired.
func TestUnwiredAdminOpsAnswerNotFound(t *testing.T) {
	t.Parallel()
	s := adminServer(t, AdminOps{})
	auth := map[string]string{"Authorization": "Bearer " + adminTok}

	cases := []struct {
		method, path, body, want string
	}{
		{http.MethodGet, "/admin/backup-health", "", "backup health is not wired"},
		{http.MethodPost, "/admin/recovery-plan", `{"source":"latest"}`, "recovery plan is not wired"},
		{http.MethodPost, "/admin/recovery-drill", `{"source":"latest"}`, "recovery drill is not wired"},
		{http.MethodPost, "/admin/restore", `{"source":"latest","confirmToken":"whatever"}`, "restore is not wired"},
	}
	for _, tc := range cases {
		w := do(t, s, tc.method, tc.path, tc.body, auth)
		if w.Code != http.StatusNotFound {
			t.Errorf("%s %s = %d, want 404 (body %s)", tc.method, tc.path, w.Code, w.Body.String())
			continue
		}
		if !strings.Contains(w.Body.String(), tc.want) {
			t.Errorf("%s %s: body %s must name the unwired operation", tc.method, tc.path, w.Body.String())
		}
	}
}

// TestAdminBackupHealthIsGetOnlyAndReadOnly covers the one report that cannot change anything.
// A method typo must not run the operation, the caller must be told which method to use, and
// the payload must be labelled readOnly so no console can offer to apply it.
func TestAdminBackupHealthIsGetOnlyAndReadOnly(t *testing.T) {
	t.Parallel()
	calls := 0
	s := adminServer(t, AdminOps{BackupHealth: func(context.Context) (any, error) {
		calls++
		return map[string]any{"localAgeSeconds": 42}, nil
	}})
	auth := map[string]string{"Authorization": "Bearer " + adminTok}

	w := do(t, s, http.MethodPost, "/admin/backup-health", `{}`, auth)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST = %d, want 405", w.Code)
	}
	if allow := w.Header().Get("Allow"); allow != http.MethodGet {
		t.Errorf("Allow = %q, want GET", allow)
	}
	if !strings.Contains(w.Body.String(), "use GET") {
		t.Errorf("the 405 must say what to use, got %s", w.Body.String())
	}
	if calls != 0 {
		t.Errorf("the report ran %d times for a rejected method", calls)
	}

	w = do(t, s, http.MethodGet, "/admin/backup-health", "", auth)
	if w.Code != http.StatusOK {
		t.Fatalf("GET = %d, want 200 (body %s)", w.Code, w.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("body %s: %v", w.Body.String(), err)
	}
	if body["readOnly"] != true {
		t.Errorf("readOnly = %v, want true so nothing offers to apply this report", body["readOnly"])
	}
	result, ok := body["result"].(map[string]any)
	if !ok || result["localAgeSeconds"] != float64(42) {
		t.Errorf("result = %v, want the operation's own answer", body["result"])
	}
	if calls != 1 {
		t.Errorf("the report ran %d times, want 1", calls)
	}
}

// A backup-health report that cannot be produced is 503 with the reason, and the attempt is on
// the record: "could not be checked" is not "everything is fine", which is what an empty 200
// would be read as.
func TestAdminBackupHealthFailureIs503(t *testing.T) {
	t.Parallel()
	s := adminServer(t, AdminOps{BackupHealth: func(context.Context) (any, error) {
		return nil, errors.New("backup directory /var/lib/wecert/backups is unreadable")
	}})

	w := do(t, s, http.MethodGet, "/admin/backup-health", "",
		map[string]string{"Authorization": "Bearer " + adminTok})
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("failed report = %d, want 503 (body %s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "is unreadable") {
		t.Errorf("the reason must reach the caller, got %s", w.Body.String())
	}

	b, err := os.ReadFile(s.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"action":"admin_backup_health"`) {
		t.Errorf("the attempt must be audited even when it fails:\n%s", b)
	}
}

// TestAdminRecoveryPlanIsPostOnlyAndDefaultsToLatestSource drives the non-destructive report.
// Omitting the source means "the newest snapshot", which is the question an operator asks
// before a restore; the answer carries readOnly so the plan cannot be mistaken for the act.
func TestAdminRecoveryPlanIsPostOnlyAndDefaultsToLatestSource(t *testing.T) {
	t.Parallel()
	var got []string
	s := adminServer(t, AdminOps{RecoveryPlan: func(_ context.Context, src string) (any, error) {
		got = append(got, src)
		return map[string]any{"source": src, "steps": []string{"verify", "swap"}}, nil
	}})
	auth := map[string]string{"Authorization": "Bearer " + adminTok}

	w := do(t, s, http.MethodGet, "/admin/recovery-plan", "", auth)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET = %d, want 405", w.Code)
	}
	if allow := w.Header().Get("Allow"); allow != http.MethodPost {
		t.Errorf("Allow = %q, want POST", allow)
	}
	if len(got) != 0 {
		t.Fatalf("a rejected method ran the plan anyway: %v", got)
	}

	// An absent body and an empty source both mean the latest snapshot.
	for _, body := range []string{"", `{}`} {
		w = do(t, s, http.MethodPost, "/admin/recovery-plan", body, auth)
		if w.Code != http.StatusOK {
			t.Fatalf("POST %q = %d, want 200 (body %s)", body, w.Code, w.Body.String())
		}
	}
	if len(got) != 2 || got[0] != "latest" || got[1] != "latest" {
		t.Fatalf("plan sources = %v, want two plans of \"latest\"", got)
	}

	// An explicit source is passed through verbatim: it may be a path or a remote name, and
	// this layer must not reinterpret it.
	w = do(t, s, http.MethodPost, "/admin/recovery-plan", `{"source":"remote:primary"}`, auth)
	if w.Code != http.StatusOK {
		t.Fatalf("explicit source = %d, want 200", w.Code)
	}
	if len(got) != 3 || got[2] != "remote:primary" {
		t.Fatalf("plan sources = %v, want the requested source last", got)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["readOnly"] != true {
		t.Errorf("readOnly = %v, want true for a plan", body["readOnly"])
	}
	if !strings.Contains(w.Body.String(), "remote:primary") {
		t.Errorf("the answer must name the source it planned, got %s", w.Body.String())
	}
}

// A plan that cannot be produced must not be answered with an empty 200: the error text is what
// tells the operator which snapshot path is wrong, and the audit line keeps the attempt.
func TestAdminRecoveryPlanFailureIsAudited(t *testing.T) {
	t.Parallel()
	s := adminServer(t, AdminOps{RecoveryPlan: func(context.Context, string) (any, error) {
		return nil, errors.New("snapshot remote:primary is not reachable")
	}})

	w := do(t, s, http.MethodPost, "/admin/recovery-plan", `{"source":"remote:primary"}`,
		map[string]string{"Authorization": "Bearer " + adminTok})
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("failed plan = %d, want 503 (body %s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "is not reachable") {
		t.Errorf("the reason must reach the caller, got %s", w.Body.String())
	}

	b, err := os.ReadFile(s.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	if !strings.Contains(text, `"action":"admin_recovery_plan"`) || !strings.Contains(text, `"source":"remote:primary"`) {
		t.Errorf("the audited attempt must name the source it was for:\n%s", text)
	}
}

// TestAdminRecoveryDrillIsPostOnlyAndMapsFailures covers the evidence route: a drill that ran
// reports what it read, and a drill that could not download or open the snapshot is 503 --
// because a drill that did not happen is not evidence that a restore works.
func TestAdminRecoveryDrillIsPostOnlyAndMapsFailures(t *testing.T) {
	t.Parallel()
	var got []string
	failing := false
	s := adminServer(t, AdminOps{RecoveryDrill: func(_ context.Context, src string) (any, error) {
		got = append(got, src)
		if failing {
			return nil, errors.New("snapshot is not a readable SQLite database")
		}
		return map[string]any{"source": src, "tables": 12}, nil
	}})
	auth := map[string]string{"Authorization": "Bearer " + adminTok}

	w := do(t, s, http.MethodGet, "/admin/recovery-drill", "", auth)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET = %d, want 405", w.Code)
	}
	if allow := w.Header().Get("Allow"); allow != http.MethodPost {
		t.Errorf("Allow = %q, want POST", allow)
	}
	if len(got) != 0 {
		t.Fatalf("a rejected method ran the drill anyway: %v", got)
	}

	// An empty source means the latest snapshot, exactly as for the plan.
	w = do(t, s, http.MethodPost, "/admin/recovery-drill", `{"source":""}`, auth)
	if w.Code != http.StatusOK {
		t.Fatalf("drill = %d, want 200 (body %s)", w.Code, w.Body.String())
	}
	if len(got) != 1 || got[0] != "latest" {
		t.Fatalf("drill sources = %v, want [latest]", got)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if _, ok := body["result"].(map[string]any); !ok {
		t.Errorf("result = %v, want the drill's evidence", body["result"])
	}

	failing = true
	w = do(t, s, http.MethodPost, "/admin/recovery-drill", `{"source":"snap.db"}`, auth)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("failed drill = %d, want 503 (body %s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "not a readable SQLite database") {
		t.Errorf("the reason must reach the caller, got %s", w.Body.String())
	}

	b, err := os.ReadFile(s.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"action":"admin_recovery_drill"`) {
		t.Errorf("the drill must be audited with the source it ran against:\n%s", b)
	}
}

// TestAdminChallengeRejectsBodiesWithoutAUsableSource covers the mint step of the two-step
// restore. The token is bound to one source string, so a challenge with no usable source has
// nothing to bind to and must mint nothing: a token that authorised "whatever comes next"
// would be the destructive-op bypass the two-step design exists to prevent.
func TestAdminChallengeRejectsBodiesWithoutAUsableSource(t *testing.T) {
	t.Parallel()
	s := adminServer(t, AdminOps{})
	auth := map[string]string{"Authorization": "Bearer " + adminTok}

	w := do(t, s, http.MethodGet, "/admin/challenge", "", auth)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET = %d, want 405", w.Code)
	}
	if allow := w.Header().Get("Allow"); allow != http.MethodPost {
		t.Errorf("Allow = %q, want POST", allow)
	}

	w = do(t, s, http.MethodPost, "/admin/challenge", `{"source":`, auth)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("truncated JSON = %d, want 400 (body %s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "body must be JSON with source") {
		t.Errorf("the 400 must name the expected body, got %s", w.Body.String())
	}

	// Whitespace is not a source: TrimSpace is what keeps " " from becoming a grant that
	// matches a path nobody meant to authorise.
	w = do(t, s, http.MethodPost, "/admin/challenge", `{"source":"   "}`, auth)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("whitespace source = %d, want 400 (body %s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "source is required") {
		t.Errorf("the 400 must explain that the source is required, got %s", w.Body.String())
	}

	if len(s.confirms) != 0 {
		t.Errorf("refused challenges minted %d tokens, want none", len(s.confirms))
	}
}

// TestAdminChallengeMintsASourceBoundToken pins the shape of the ticket: 16 random bytes in
// hex, an expiry the caller can plan around, and a stored grant whose source is exactly the
// one echoed in the response. Anything guessable -- a timestamp, a counter -- would let a
// caller that can reach the admin token mint its own restore ticket offline.
func TestAdminChallengeMintsASourceBoundToken(t *testing.T) {
	t.Parallel()
	s := adminServer(t, AdminOps{})
	base := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return base }

	w := do(t, s, http.MethodPost, "/admin/challenge", `{"source":"remote:primary"}`,
		map[string]string{"Authorization": "Bearer " + adminTok})
	if w.Code != http.StatusOK {
		t.Fatalf("challenge = %d, want 200 (body %s)", w.Code, w.Body.String())
	}
	var body struct {
		ConfirmToken string `json:"confirmToken"`
		ExpiresAt    string `json:"expiresAt"`
		Action       string `json:"action"`
		Source       string `json:"source"`
		Hint         string `json:"hint"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("body %s: %v", w.Body.String(), err)
	}
	if len(body.ConfirmToken) != 32 {
		t.Errorf("confirmToken = %q (%d chars), want 16 random bytes in hex", body.ConfirmToken, len(body.ConfirmToken))
	}
	if _, err := hex.DecodeString(body.ConfirmToken); err != nil {
		t.Errorf("confirmToken = %q is not hex: %v", body.ConfirmToken, err)
	}
	if body.Action != "restore" || body.Source != "remote:primary" {
		t.Errorf("action/source = %q/%q, want the restore of the requested source", body.Action, body.Source)
	}
	if want := base.Add(adminConfirmTTL).UTC().Format(time.RFC3339); body.ExpiresAt != want {
		t.Errorf("expiresAt = %q, want %q (the documented %s TTL)", body.ExpiresAt, want, adminConfirmTTL)
	}
	if !strings.Contains(body.Hint, "/admin/restore") {
		t.Errorf("hint = %q, want it to name the route that consumes the token", body.Hint)
	}

	grant, ok := s.confirms[body.ConfirmToken]
	if !ok {
		t.Fatalf("the minted token is not registered: %v", s.confirms)
	}
	if grant.source != "remote:primary" {
		t.Errorf("grant source = %q, want the source the response echoed", grant.source)
	}
	if !grant.expires.Equal(base.Add(adminConfirmTTL)) {
		t.Errorf("grant expiry = %s, want %s", grant.expires, base.Add(adminConfirmTTL))
	}
}

// TestAdminChallengePrunesExpiredTickets covers the sweep that keeps the confirm map bounded.
// A monitoring loop that polls /admin/challenge would otherwise grow it without limit, and the
// sweep must take only the tickets that are already dead: dropping a live one would invalidate
// a token an operator is holding right now.
func TestAdminChallengePrunesExpiredTickets(t *testing.T) {
	t.Parallel()
	s := adminServer(t, AdminOps{})
	base := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return base }
	s.confirms = map[string]confirmGrant{
		"expired-ticket": {expires: base.Add(-time.Minute), source: "latest"},
		"live-ticket":    {expires: base.Add(time.Minute), source: "remote:primary"},
	}

	w := do(t, s, http.MethodPost, "/admin/challenge", `{"source":"latest"}`,
		map[string]string{"Authorization": "Bearer " + adminTok})
	if w.Code != http.StatusOK {
		t.Fatalf("challenge = %d, want 200 (body %s)", w.Code, w.Body.String())
	}
	var body struct {
		ConfirmToken string `json:"confirmToken"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}

	if _, ok := s.confirms["expired-ticket"]; ok {
		t.Error("an expired ticket must be swept on the next challenge")
	}
	if _, ok := s.confirms["live-ticket"]; !ok {
		t.Error("a live ticket must survive the sweep")
	}
	if _, ok := s.confirms[body.ConfirmToken]; !ok {
		t.Error("the token just minted must be registered")
	}
}

// TestAdminRestoreGuardsItsInput walks the destructive route's refusals in the order they are
// applied: method, then a body that can be read, then a source, then a confirm token. Each one
// must stop before the restore operation runs -- a rejected request that still replaced
// state.db would be the worst possible reading of "the guard worked".
func TestAdminRestoreGuardsItsInput(t *testing.T) {
	t.Parallel()
	restored := 0
	s := adminServer(t, AdminOps{Restore: func(_ context.Context, src string) (any, error) {
		restored++
		return map[string]any{"source": src}, nil
	}})
	auth := map[string]string{"Authorization": "Bearer " + adminTok}

	w := do(t, s, http.MethodGet, "/admin/restore", "", auth)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET = %d, want 405", w.Code)
	}
	if allow := w.Header().Get("Allow"); allow != http.MethodPost {
		t.Errorf("Allow = %q, want POST", allow)
	}

	w = do(t, s, http.MethodPost, "/admin/restore", `{"source":`, auth)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("truncated JSON = %d, want 400 (body %s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "body must be JSON") {
		t.Errorf("the 400 must name the expected body, got %s", w.Body.String())
	}

	// No source: the confirm token is bound to one, so there is nothing to match it against.
	w = do(t, s, http.MethodPost, "/admin/restore", `{"confirmToken":"whatever"}`, auth)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("missing source = %d, want 400 (body %s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "source is required") {
		t.Errorf("the 400 must explain that a source is required, got %s", w.Body.String())
	}

	// A token that was never issued is refused, and the refusal says how to get one.
	w = do(t, s, http.MethodPost, "/admin/restore", `{"source":"latest","confirmToken":"deadbeef"}`, auth)
	if w.Code != http.StatusForbidden {
		t.Fatalf("unissued token = %d, want 403 (body %s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "POST /admin/challenge") {
		t.Errorf("the refusal must point at the challenge route, got %s", w.Body.String())
	}
	if restored != 0 {
		t.Fatalf("a refused restore ran the operation %d times", restored)
	}

	b, err := os.ReadFile(s.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"reason":"missing"`) {
		t.Errorf("the audit line must say the token was missing:\n%s", b)
	}
}

// TestAdminRestoreRefusesExpiredAndUnboundTickets pins the two refusals that are not about the
// caller's token being absent: a ticket that has aged out, and a ticket with no source bound to
// it. They get different answers on purpose -- "missing or expired" for a source mismatch
// trains an operator to re-issue the same token forever, and a wildcard grant must never be
// honoured, because the whole point of the challenge step is that a token authorises exactly
// one restore source.
func TestAdminRestoreRefusesExpiredAndUnboundTickets(t *testing.T) {
	t.Parallel()
	restored := 0
	s := adminServer(t, AdminOps{Restore: func(_ context.Context, src string) (any, error) {
		restored++
		return map[string]any{"source": src}, nil
	}})
	base := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return base }
	s.confirms = map[string]confirmGrant{
		"expired-ticket": {expires: base.Add(-time.Minute), source: "latest"},
		"unbound-ticket": {expires: base.Add(time.Minute), source: ""},
	}
	auth := map[string]string{"Authorization": "Bearer " + adminTok}

	w := do(t, s, http.MethodPost, "/admin/restore",
		`{"source":"latest","confirmToken":"expired-ticket"}`, auth)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expired ticket = %d, want 403 (body %s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "expired") {
		t.Errorf("the refusal must say the ticket expired, got %s", w.Body.String())
	}

	// A grant with an empty source is refused rather than read as "any source".
	w = do(t, s, http.MethodPost, "/admin/restore",
		`{"source":"latest","confirmToken":"unbound-ticket"}`, auth)
	if w.Code != http.StatusForbidden {
		t.Fatalf("unbound ticket = %d, want 403 (body %s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "not bound to a source") {
		t.Errorf("the refusal must say the ticket is unbound, got %s", w.Body.String())
	}
	if restored != 0 {
		t.Fatalf("a refused restore ran the operation %d times", restored)
	}

	// Refusing is still consuming: the first ticket is spent, so a replay is answered as a
	// missing token rather than as another expired one.
	w = do(t, s, http.MethodPost, "/admin/restore",
		`{"source":"latest","confirmToken":"expired-ticket"}`, auth)
	if w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), "expired") {
		t.Errorf("a spent ticket = %d %s, want a plain missing-token refusal", w.Code, w.Body.String())
	}

	b, err := os.ReadFile(s.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	for _, want := range []string{
		`"action":"admin_restore_refused"`,
		`"reason":"expired"`,
		`"reason":"wildcard_token"`,
		`"reason":"missing"`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the audit log is missing %s:\n%s", want, text)
		}
	}
}

// TestAdminRestoreFailureIsAuditedAndNotStaged covers a restore that was authorised and ran but
// could not finish. It is a 503 with the reason, it is on the record as failed, and it must NOT
// be recorded as staged: the staged line tells the operator to restart into the new database,
// and restarting into one that was never replaced is how a bad snapshot becomes an outage.
func TestAdminRestoreFailureIsAuditedAndNotStaged(t *testing.T) {
	t.Parallel()
	attempts := 0
	s := adminServer(t, AdminOps{Restore: func(_ context.Context, src string) (any, error) {
		attempts++
		return nil, errors.New("state.db is not a wecert snapshot")
	}})
	auth := map[string]string{"Authorization": "Bearer " + adminTok}

	w := do(t, s, http.MethodPost, "/admin/challenge", `{"source":"latest"}`, auth)
	if w.Code != http.StatusOK {
		t.Fatalf("challenge = %d (body %s)", w.Code, w.Body.String())
	}
	var ch struct {
		ConfirmToken string `json:"confirmToken"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &ch); err != nil || ch.ConfirmToken == "" {
		t.Fatalf("challenge body %s (%v)", w.Body.String(), err)
	}

	w = do(t, s, http.MethodPost, "/admin/restore",
		`{"source":"latest","confirmToken":"`+ch.ConfirmToken+`"}`, auth)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("failed restore = %d, want 503 (body %s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "not a wecert snapshot") {
		t.Errorf("the reason must reach the caller, got %s", w.Body.String())
	}
	if attempts != 1 {
		t.Fatalf("restore attempts = %d, want 1", attempts)
	}

	b, err := os.ReadFile(s.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	if !strings.Contains(text, `"action":"admin_restore_failed"`) || !strings.Contains(text, "not a wecert snapshot") {
		t.Errorf("the failure must be on the record with its reason:\n%s", text)
	}
	if strings.Contains(text, "admin_restore_staged") {
		t.Errorf("a failed restore must not be reported as staged:\n%s", text)
	}

	// The ticket is spent even though the restore failed: a retry needs a new challenge, so
	// a transient failure cannot be replayed by an old request in a log.
	w = do(t, s, http.MethodPost, "/admin/restore",
		`{"source":"latest","confirmToken":"`+ch.ConfirmToken+`"}`, auth)
	if w.Code != http.StatusForbidden || attempts != 1 {
		t.Errorf("replay of a spent ticket = %d attempts=%d, want 403 and no second attempt", w.Code, attempts)
	}
}

// TestAdminAuditLinesAreMachineReadable pins the record's shape. The file is read by log
// shippers, not by people: one self-contained JSON object per request, with the instant, the
// action, the path and the address the request came from -- a line missing any of them cannot
// be attributed to an actor or a route.
func TestAdminAuditLinesAreMachineReadable(t *testing.T) {
	t.Parallel()
	s := adminServer(t, AdminOps{BackupHealth: func(context.Context) (any, error) {
		return map[string]any{"ok": true}, nil
	}})

	req := httptest.NewRequest(http.MethodGet, "/admin/backup-health", nil)
	req.Header.Set("Authorization", "Bearer "+adminTok)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	b, err := os.ReadFile(s.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 1 {
		t.Fatalf("audit lines = %d, want one per request:\n%s", len(lines), b)
	}
	var rec map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatalf("audit line is not one JSON object: %v (%q)", err, lines[0])
	}
	if rec["action"] != "admin_backup_health" {
		t.Errorf("action = %v, want the action that ran", rec["action"])
	}
	if rec["path"] != "/admin/backup-health" {
		t.Errorf("path = %v, want the request path", rec["path"])
	}
	if rec["remote"] != req.RemoteAddr {
		t.Errorf("remote = %v, want the transport address %q", rec["remote"], req.RemoteAddr)
	}
	if at, _ := rec["at"].(string); at == "" {
		t.Errorf("at = %v, want an instant the journal can be ordered by", rec["at"])
	} else if _, err := time.Parse(time.RFC3339Nano, at); err != nil {
		t.Errorf("at = %q is not RFC3339Nano: %v", at, err)
	}
}

// An audit record that cannot be encoded must be dropped whole. json.Marshal runs before the
// file is opened, so the failure can never leave a half-written line behind -- and a partial
// line is worse than a missing one, because it breaks every line that follows it in the file.
func TestAdminAuditDropsWhatItCannotMarshal(t *testing.T) {
	t.Parallel()
	s := adminOpsServer(t, AdminOps{}, t.TempDir()+"/audit.jsonl", nil)

	s.audit(httptest.NewRequest(http.MethodGet, "/admin/backup-health", nil),
		"admin_unencodable", map[string]any{"ch": make(chan int)})

	if _, err := os.Stat(s.auditPath); !os.IsNotExist(err) {
		b, _ := os.ReadFile(s.auditPath)
		t.Errorf("an unencodable record must not be written, got %q (stat err %v)", b, err)
	}
}

// A sink that cannot be opened is the audit trail's problem, not the caller's: the operator
// still gets the answer, and the journal gets the warning because the audit file is now
// silently incomplete.
func TestAdminAuditOpenFailureDoesNotFailTheRequest(t *testing.T) {
	t.Parallel()
	var logs bytes.Buffer
	calls := 0
	// A directory is a sink that opens for nobody.
	s := adminOpsServer(t, AdminOps{BackupHealth: func(context.Context) (any, error) {
		calls++
		return map[string]any{"ok": true}, nil
	}}, t.TempDir(), &logs)

	w := do(t, s, http.MethodGet, "/admin/backup-health", "",
		map[string]string{"Authorization": "Bearer " + adminTok})
	if w.Code != http.StatusOK {
		t.Fatalf("a broken audit sink must not fail the request: %d (body %s)", w.Code, w.Body.String())
	}
	if calls != 1 {
		t.Errorf("the report ran %d times, want 1", calls)
	}
	if !strings.Contains(logs.String(), "cannot write the admin audit log") {
		t.Errorf("the unwritable sink must reach the log, got:\n%s", logs.String())
	}
}

// A sink that opens but rejects the append is the case a full disk produces. It is the more
// dangerous one of the two: the open succeeded, so only the write error reveals that the audit
// trail is incomplete -- and the request must still be answered.
func TestAdminAuditAppendFailureIsLogged(t *testing.T) {
	t.Parallel()
	probe, err := os.OpenFile("/dev/full", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Skipf("no /dev/full to stand in for a full disk: %v", err)
	}
	_, werr := probe.Write([]byte("x"))
	_ = probe.Close()
	if werr == nil {
		t.Skip("/dev/full accepted a write, so it cannot simulate a full disk here")
	}

	var logs bytes.Buffer
	s := adminOpsServer(t, AdminOps{BackupHealth: func(context.Context) (any, error) {
		return map[string]any{"ok": true}, nil
	}}, "/dev/full", &logs)

	w := do(t, s, http.MethodGet, "/admin/backup-health", "",
		map[string]string{"Authorization": "Bearer " + adminTok})
	if w.Code != http.StatusOK {
		t.Fatalf("a full audit sink must not fail the request: %d (body %s)", w.Code, w.Body.String())
	}
	if !strings.Contains(logs.String(), "cannot append to the admin audit log") {
		t.Errorf("the dropped audit line must reach the log, got:\n%s", logs.String())
	}
}
