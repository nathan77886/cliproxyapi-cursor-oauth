package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func oauthManagerForTest(t *testing.T, handler http.HandlerFunc) *cursorOAuthManager {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	m := newCursorOAuthManager()
	m.backendURL = server.URL
	m.newClient = func(string) (*http.Client, error) {
		client := server.Client()
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		return client, nil
	}
	t.Cleanup(m.close)
	return m
}

func beginCursorLogin(t *testing.T, m *cursorOAuthManager) pluginapi.AuthLoginStartResponse {
	t.Helper()
	response, err := m.start(pluginapi.AuthLoginStartRequest{Provider: "cursor"})
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func TestCursorBrowserLoginHandshake(t *testing.T) {
	t.Parallel()
	m := oauthManagerForTest(t, func(http.ResponseWriter, *http.Request) { t.Error("start must not call the upstream") })
	first := beginCursorLogin(t, m)
	second := beginCursorLogin(t, m)
	u, err := url.Parse(first.URL)
	if err != nil || u.Scheme != "https" || u.Host != "cursor.com" || u.Path != "/loginDeepControl" {
		t.Fatalf("unexpected login URL: %s", first.URL)
	}
	query := u.Query()
	session := m.sessions[first.State]
	hash := sha256.Sum256([]byte(session.verifier))
	if query.Get("challenge") != base64.RawURLEncoding.EncodeToString(hash[:]) || query.Get("uuid") != session.uuid {
		t.Fatal("login URL does not bind the browser to this PKCE verifier")
	}
	if query.Get("mode") != "login" || query.Get("redirectTarget") != "sdk" {
		t.Fatal("login must use the official SDK confirmation page")
	}
	if first.State == second.State || session.verifier == m.sessions[second.State].verifier {
		t.Fatal("independent attempts must not share secrets")
	}
	encoded, _ := json.Marshal(first)
	if strings.Contains(string(encoded), session.verifier) || len(first.Metadata) != 0 {
		t.Fatal("PKCE verifier escaped into a start response")
	}
	if _, err := m.start(pluginapi.AuthLoginStartRequest{Provider: "codex"}); err == nil {
		t.Fatal("accepted another provider")
	}
}

func TestCursorBrowserLoginMintsAndPreservesCredential(t *testing.T) {
	t.Parallel()
	var minted atomic.Int32
	now := time.Now().UTC().Truncate(time.Second)
	m := oauthManagerForTest(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.RawQuery != "" {
			t.Error("login secrets must be sent by POST without query parameters")
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/auth/poll":
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if len(body["verifier"]) < 40 || body["uuid"] == "" || r.Header.Get("Authorization") != "" {
				t.Error("invalid poll handshake")
			}
			_, _ = w.Write([]byte(`{"accessToken":"test-session-secret","refreshToken":"never-store-this"}`))
		case cursorDashboardRPC + "GetMe":
			if r.Header.Get("Authorization") != "Bearer test-session-secret" {
				t.Error("identity call has no browser authorization")
			}
			_, _ = w.Write([]byte(`{"email":"friend@example.com"}`))
		case cursorDashboardRPC + "CreateUserApiKey":
			minted.Add(1)
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["expiresAt"] != strconv.FormatInt(now.Add(cursorAPIKeyTTL).UnixMilli(), 10) || !strings.HasPrefix(body["name"], "CLIProxyAPI Cursor ") {
				t.Error("key must be named and expire after 90 days")
			}
			if r.Header.Get("Connect-Protocol-Version") != "1" || r.Header.Get("Authorization") != "Bearer test-session-secret" {
				t.Error("invalid Connect authorization")
			}
			_, _ = w.Write([]byte(`{"apiKey":"test-minted-api-key"}`))
		default:
			t.Errorf("unexpected request: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})
	m.now = func() time.Time { return now }
	start := beginCursorLogin(t, m)
	dir := t.TempDir()
	existing := `{"type":"cursor","apiKey":"old-key","expiresAt":"2000-01-01T00:00:00Z","prefix":"private","disabled":true,"note":"keep me","proxy_url":"http://localhost:7890"}`
	if err := os.WriteFile(filepath.Join(dir, "cursor-friend-example.com.json"), []byte(existing), 0600); err != nil {
		t.Fatal(err)
	}
	req := pluginapi.AuthLoginPollRequest{Provider: "cursor", State: start.State, Host: pluginapi.HostConfigSummary{AuthDir: dir}}
	response := m.poll(req)
	if response.Status != pluginapi.AuthLoginStatusSuccess {
		t.Fatalf("login failed: %s", response.Message)
	}
	var storage map[string]any
	if err := json.Unmarshal(response.Auth.StorageJSON, &storage); err != nil {
		t.Fatal(err)
	}
	if storage["api_key"] != "test-minted-api-key" || storage["type"] != "cursor" || storage["email"] != "friend@example.com" {
		t.Fatal("missing credential or account identity")
	}
	if storage["prefix"] != "private" || storage["note"] != "keep me" || !response.Auth.Disabled || response.Auth.ProxyURL != "http://localhost:7890" {
		t.Fatal("renewal lost operator-owned account settings")
	}
	if _, old := storage["apiKey"]; old {
		t.Fatal("legacy API key spelling survived renewal")
	}
	if expiryFromStorage(response.Auth.StorageJSON) != now.Add(cursorAPIKeyTTL) {
		t.Fatal("stored key has no correct expiration")
	}
	encoded, _ := json.Marshal(response)
	for _, secret := range []string{"test-session-secret", "never-store-this", m.sessions[start.State].uuid} {
		if strings.Contains(string(encoded), secret) {
			t.Fatal("browser session secrets survived into the persisted auth")
		}
	}
	if again := m.poll(req); again.Status != pluginapi.AuthLoginStatusSuccess || minted.Load() != 1 {
		t.Fatal("repeated polling minted more than one key")
	}
	if m.sessions[start.State].verifier != "" {
		t.Fatal("completed login retained its verifier")
	}
}

func TestCursorBrowserLoginPendingAndFailures(t *testing.T) {
	for _, test := range []struct {
		name   string
		status int
		body   string
		want   pluginapi.AuthLoginStatus
	}{
		{"awaiting email verification", 404, "Not found", pluginapi.AuthLoginStatusPending},
		{"rate limited", 429, "secret-upstream-body", pluginapi.AuthLoginStatusPending},
		{"not authorized", 403, "secret-upstream-body", pluginapi.AuthLoginStatusError},
		{"empty token", 200, `{}`, pluginapi.AuthLoginStatusError},
		{"malformed response", 200, `secret-upstream-body`, pluginapi.AuthLoginStatusError},
		{"oversized response", 200, strings.Repeat("s", cursorOAuthMaxBody+1), pluginapi.AuthLoginStatusError},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			m := oauthManagerForTest(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/auth/poll" {
					t.Error("an incomplete login must not create a key")
				}
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			})
			start := beginCursorLogin(t, m)
			response := m.poll(pluginapi.AuthLoginPollRequest{Provider: "cursor", State: start.State})
			if response.Status != test.want || strings.Contains(response.Message, "secret-upstream-body") || len(response.Auth.StorageJSON) != 0 {
				t.Fatalf("unexpected login result: %s %s", response.Status, response.Message)
			}
		})
	}
}

func TestCursorBrowserLoginConcurrentPollsMintOnce(t *testing.T) {
	t.Parallel()
	entered, release := make(chan struct{}), make(chan struct{})
	var minted atomic.Int32
	m := oauthManagerForTest(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/poll":
			close(entered)
			<-release
			_, _ = w.Write([]byte(`{"accessToken":"test-access"}`))
		case cursorDashboardRPC + "GetMe":
			_, _ = w.Write([]byte(`{"email":"test@example.com"}`))
		default:
			minted.Add(1)
			_, _ = w.Write([]byte(`{"apiKey":"test-key"}`))
		}
	})
	start := beginCursorLogin(t, m)
	req := pluginapi.AuthLoginPollRequest{State: start.State}
	done := make(chan pluginapi.AuthLoginPollResponse, 1)
	go func() { done <- m.poll(req) }()
	<-entered
	second := m.poll(req)
	close(release)
	first := <-done
	if second.Status != pluginapi.AuthLoginStatusPending || first.Status != pluginapi.AuthLoginStatusSuccess || minted.Load() != 1 {
		t.Fatal("concurrent poll issued duplicate key creation")
	}
}

func TestCursorBrowserLoginExpiresAndCancellation(t *testing.T) {
	t.Parallel()
	m := oauthManagerForTest(t, func(http.ResponseWriter, *http.Request) { t.Error("expired attempts must not call Cursor") })
	now := time.Now()
	m.now = func() time.Time { return now }
	start := beginCursorLogin(t, m)
	now = now.Add(cursorOAuthTTL + time.Second)
	if response := m.poll(pluginapi.AuthLoginPollRequest{State: start.State}); response.Status != pluginapi.AuthLoginStatusError {
		t.Fatal("expired login accepted")
	}
	start = beginCursorLogin(t, m)
	m.remove(start.State)
	if response := m.poll(pluginapi.AuthLoginPollRequest{State: start.State}); response.Status != pluginapi.AuthLoginStatusError {
		t.Fatal("cancelled login accepted")
	}
}

func TestCursorBrowserLoginRefusesCredentialRedirect(t *testing.T) {
	t.Parallel()
	var leaked atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { leaked.Add(1) }))
	t.Cleanup(target.Close)
	m := oauthManagerForTest(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", target.URL)
		w.WriteHeader(http.StatusTemporaryRedirect)
	})
	start := beginCursorLogin(t, m)
	if response := m.poll(pluginapi.AuthLoginPollRequest{State: start.State}); response.Status != pluginapi.AuthLoginStatusError || leaked.Load() != 0 {
		t.Fatal("followed a redirect carrying login credentials")
	}
}

func TestCursorBrowserLoginKeyCreationFailureDoesNotLeakTokens(t *testing.T) {
	t.Parallel()
	var minted atomic.Int32
	m := oauthManagerForTest(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/poll":
			_, _ = w.Write([]byte(`{"accessToken":"do-not-expose"}`))
		case cursorDashboardRPC + "GetMe":
			w.WriteHeader(http.StatusForbidden)
		default:
			minted.Add(1)
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"message":"do-not-expose"}`))
		}
	})
	start := beginCursorLogin(t, m)
	req := pluginapi.AuthLoginPollRequest{State: start.State}
	for range 2 {
		response := m.poll(req)
		if response.Status != pluginapi.AuthLoginStatusError || strings.Contains(response.Message, "do-not-expose") || len(response.Auth.StorageJSON) != 0 {
			t.Fatal("failed key creation returned credentials")
		}
	}
	if minted.Load() != 1 {
		t.Fatal("failed key creation was retried and could mint duplicate keys")
	}
}

func TestCursorBrowserLoginLimitsPendingAttempts(t *testing.T) {
	t.Parallel()
	m := oauthManagerForTest(t, func(http.ResponseWriter, *http.Request) {})
	for range cursorOAuthMaxFlows {
		beginCursorLogin(t, m)
	}
	if _, err := m.start(pluginapi.AuthLoginStartRequest{}); err == nil {
		t.Fatal("unbounded login attempts were accepted")
	}
}
