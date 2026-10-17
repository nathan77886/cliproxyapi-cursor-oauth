package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

const (
	cursorOAuthTTL      = 10 * time.Minute
	cursorAPIKeyTTL     = 90 * 24 * time.Hour
	cursorOAuthMaxFlows = 64
	cursorOAuthMaxBody  = 1 << 20
	cursorDashboardRPC  = "/aiserver.v1.DashboardService/"
)

// The SDK's browser handshake produces a short-lived access token. Use it once to
// mint an expiring user API key, then retain only that key in the host auth file.
type cursorOAuthSession struct {
	mu        sync.Mutex
	uuid      string
	verifier  string
	expiresAt time.Time
	nextPoll  time.Time
	ctx       context.Context
	cancel    context.CancelFunc
	client    *http.Client
	timer     *time.Timer
	result    *pluginapi.AuthLoginPollResponse
}

type cursorOAuthManager struct {
	mu         sync.Mutex
	sessions   map[string]*cursorOAuthSession
	websiteURL string
	backendURL string
	now        func() time.Time
	newClient  func(string) (*http.Client, error)
}

func newCursorOAuthManager() *cursorOAuthManager {
	return &cursorOAuthManager{
		sessions:   make(map[string]*cursorOAuthSession),
		websiteURL: "https://cursor.com",
		backendURL: "https://api2.cursor.sh",
		now:        time.Now,
		newClient:  newCursorOAuthHTTPClient,
	}
}

var cursorLogins = newCursorOAuthManager()

func newCursorOAuthHTTPClient(proxyURL string) (*http.Client, error) {
	var proxy *url.URL
	if configured := resolveEgressProxy(proxyURL); configured != "" {
		parsed, err := parseEgressProxy(configured)
		if err != nil {
			return nil, errors.New("Cursor login proxy configuration is invalid")
		}
		proxy = parsed
	}
	transport := egressTransport(proxy)
	transport.ResponseHeaderTimeout = 15 * time.Second
	return &http.Client{
		Transport: transport,
		Timeout:   20 * time.Second,
		// Credentials must never be redirected to a different host.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

func loginStart(raw []byte) ([]byte, error) {
	var req pluginapi.AuthLoginStartRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	response, err := cursorLogins.start(req)
	if err != nil {
		return errorEnvelope("cursor_login_failed", err.Error()), nil
	}
	return okEnvelope(response)
}

func loginPoll(raw []byte) ([]byte, error) {
	var req pluginapi.AuthLoginPollRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	return okEnvelope(cursorLogins.poll(req))
}

func (m *cursorOAuthManager) start(req pluginapi.AuthLoginStartRequest) (pluginapi.AuthLoginStartResponse, error) {
	if req.Provider != "" && req.Provider != providerIdentifier {
		return pluginapi.AuthLoginStartResponse{}, errors.New("unsupported Cursor login provider")
	}
	client, err := m.newClient(loadedConfig().ProxyURL)
	if err != nil {
		return pluginapi.AuthLoginStartResponse{}, err
	}
	verifier := base64.RawURLEncoding.EncodeToString(randomBytes(32))
	state := base64.RawURLEncoding.EncodeToString(randomBytes(32))
	challenge := sha256.Sum256([]byte(verifier))
	uuidBytes := randomBytes(16)
	uuidBytes[6] = uuidBytes[6]&0x0f | 0x40
	uuidBytes[8] = uuidBytes[8]&0x3f | 0x80
	uuid := fmt.Sprintf("%x-%x-%x-%x-%x", uuidBytes[:4], uuidBytes[4:6], uuidBytes[6:8], uuidBytes[8:10], uuidBytes[10:])
	expires := m.now().Add(cursorOAuthTTL)
	ctx, cancel := context.WithTimeout(context.Background(), cursorOAuthTTL)
	session := &cursorOAuthSession{uuid: uuid, verifier: verifier, expiresAt: expires, ctx: ctx, cancel: cancel, client: client}
	m.mu.Lock()
	if len(m.sessions) >= cursorOAuthMaxFlows {
		m.mu.Unlock()
		cancel()
		client.CloseIdleConnections()
		return pluginapi.AuthLoginStartResponse{}, errors.New("too many pending Cursor logins; retry after an existing login expires")
	}
	m.sessions[state] = session
	session.timer = time.AfterFunc(cursorOAuthTTL, func() { m.remove(state) })
	m.mu.Unlock()
	query := url.Values{
		"challenge":      {base64.RawURLEncoding.EncodeToString(challenge[:])},
		"uuid":           {uuid},
		"mode":           {"login"},
		"redirectTarget": {"sdk"},
	}
	return pluginapi.AuthLoginStartResponse{
		Provider:  providerIdentifier,
		URL:       m.websiteURL + "/loginDeepControl?" + query.Encode(),
		State:     state,
		ExpiresAt: expires,
		// The PKCE verifier stays in this process, never in host metadata or a URL.
	}, nil
}

func randomBytes(size int) []byte {
	b := make([]byte, size)
	_, _ = rand.Read(b) // crypto/rand.Read cannot fail on supported Go platforms.
	return b
}

func (m *cursorOAuthManager) poll(req pluginapi.AuthLoginPollRequest) pluginapi.AuthLoginPollResponse {
	m.mu.Lock()
	session := m.sessions[req.State]
	m.mu.Unlock()
	if session == nil {
		return cursorLoginError("Cursor login expired or was cancelled; start a new login")
	}
	if !session.mu.TryLock() {
		return pluginapi.AuthLoginPollResponse{Status: pluginapi.AuthLoginStatusPending}
	}
	defer session.mu.Unlock()
	if req.Provider != "" && req.Provider != providerIdentifier {
		return cursorLoginError("unsupported Cursor login provider")
	}
	if !m.now().Before(session.expiresAt) || session.ctx.Err() != nil {
		m.remove(req.State)
		return cursorLoginError("Cursor login expired; start a new login")
	}
	if session.result != nil {
		return *session.result
	}
	if m.now().Before(session.nextPoll) {
		return pluginapi.AuthLoginPollResponse{Status: pluginapi.AuthLoginStatusPending}
	}
	session.nextPoll = m.now().Add(2 * time.Second)
	response := m.pollUpstream(session, req.Host.AuthDir)
	if response.Status != pluginapi.AuthLoginStatusPending {
		session.result = &response
		session.verifier = ""
		session.client.CloseIdleConnections()
	}
	return response
}

func (m *cursorOAuthManager) pollUpstream(session *cursorOAuthSession, authDir string) pluginapi.AuthLoginPollResponse {
	ctx, cancel := context.WithTimeout(session.ctx, 25*time.Second)
	defer cancel()
	var tokens struct {
		AccessToken string `json:"accessToken"`
	}
	status, err := m.post(ctx, session, "/auth/poll", "", map[string]string{"uuid": session.uuid, "verifier": session.verifier}, &tokens)
	if err != nil {
		return cursorLoginError("could not reach Cursor login; start a new login and retry")
	}
	if status == http.StatusNotFound || status == http.StatusAccepted || status == http.StatusNoContent || status == http.StatusTooManyRequests {
		if status == http.StatusTooManyRequests {
			session.nextPoll = m.now().Add(15 * time.Second)
		}
		return pluginapi.AuthLoginPollResponse{Status: pluginapi.AuthLoginStatusPending}
	}
	if status != http.StatusOK || strings.TrimSpace(tokens.AccessToken) == "" {
		return cursorLoginError("Cursor did not complete browser authorization; start a new login")
	}
	var identity struct {
		Email string `json:"email"`
	}
	// Identity is optional in the official SDK. A stable key digest names the auth
	// file if this read is unavailable, so simultaneous logins cannot overwrite it.
	_, _ = m.post(ctx, session, cursorDashboardRPC+"GetMe", tokens.AccessToken, struct{}{}, &identity)
	expires := m.now().Add(cursorAPIKeyTTL)
	var minted struct {
		APIKey string `json:"apiKey"`
	}
	status, err = m.post(ctx, session, cursorDashboardRPC+"CreateUserApiKey", tokens.AccessToken, map[string]string{
		"name":      "CLIProxyAPI Cursor " + m.now().UTC().Format("2006-01-02 15:04:05"),
		"expiresAt": strconv.FormatInt(expires.UnixMilli(), 10),
	}, &minted)
	if err != nil || status != http.StatusOK || strings.TrimSpace(minted.APIKey) == "" {
		return cursorLoginError("Cursor browser login succeeded, but creating an API key failed; check the account or team's user API key policy and sign in again")
	}
	auth, err := (loginCredential{apiKey: minted.APIKey, email: strings.TrimSpace(identity.Email), expiresAt: expires}).authData(authDir)
	if err != nil {
		return cursorLoginError("Cursor credential could not be prepared; start a new login")
	}
	return pluginapi.AuthLoginPollResponse{Status: pluginapi.AuthLoginStatusSuccess, Auth: auth}
}

// post intentionally has no GET fallback: a PKCE verifier in a query string can
// leak through proxy/access logs. Errors and upstream bodies are never reflected.
func (m *cursorOAuthManager) post(ctx context.Context, session *cursorOAuthSession, path, token string, payload, out any) (int, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return 0, errors.New("could not encode Cursor login request")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.backendURL+path, bytes.NewReader(body))
	if err != nil {
		return 0, errors.New("could not prepare Cursor login request")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Connect-Protocol-Version", "1")
	}
	response, err := session.client.Do(req)
	if err != nil {
		return 0, errors.New("Cursor login request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return response.StatusCode, nil
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, cursorOAuthMaxBody+1))
	if err != nil || len(raw) > cursorOAuthMaxBody {
		return response.StatusCode, errors.New("invalid Cursor login response")
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return response.StatusCode, errors.New("invalid Cursor login response")
	}
	return response.StatusCode, nil
}

func cursorLoginError(message string) pluginapi.AuthLoginPollResponse {
	return pluginapi.AuthLoginPollResponse{Status: pluginapi.AuthLoginStatusError, Message: message}
}

func (m *cursorOAuthManager) remove(state string) {
	m.mu.Lock()
	session := m.sessions[state]
	delete(m.sessions, state)
	m.mu.Unlock()
	if session != nil {
		session.timer.Stop()
		session.cancel()
		session.client.CloseIdleConnections()
	}
}

func (m *cursorOAuthManager) close() {
	m.mu.Lock()
	sessions := m.sessions
	m.sessions = make(map[string]*cursorOAuthSession)
	m.mu.Unlock()
	for _, session := range sessions {
		session.timer.Stop()
		session.cancel()
		session.client.CloseIdleConnections()
	}
}

func stopOAuthLogins() { cursorLogins.close() }
