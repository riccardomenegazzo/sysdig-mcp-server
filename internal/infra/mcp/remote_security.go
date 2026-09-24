package mcp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/mark3labs/mcp-go/server"
	infraauth "github.com/sysdiglabs/sysdig-mcp-server/internal/infra/auth"
)

const (
	sessionIDPrefix          = "mcp-session-"
	principalFingerprintSize = 16
	sessionNonceSize         = 16
)

type principalContextKey struct{}

type RemoteSecurity struct {
	verifier           infraauth.TokenVerifier
	allowedOrigins     map[string]struct{}
	corsAllowedOrigins []string
	metadata           server.ProtectedResourceMetadataConfig
	metadataURL        string
}

func NewRemoteSecurity(
	verifier infraauth.TokenVerifier,
	resourceURL string,
	authorizationServer string,
	requiredScopes []string,
	allowedOrigins []string,
) RemoteSecurity {
	origins := make(map[string]struct{}, len(allowedOrigins))
	corsOrigins := make([]string, 0, len(allowedOrigins))
	for _, origin := range allowedOrigins {
		normalized := normalizeOrigin(origin)
		if _, exists := origins[normalized]; exists {
			continue
		}
		origins[normalized] = struct{}{}
		corsOrigins = append(corsOrigins, normalized)
	}

	metadata := server.ProtectedResourceMetadataConfig{
		Resource:               resourceURL,
		AuthorizationServers:   []string{authorizationServer},
		ScopesSupported:        requiredScopes,
		BearerMethodsSupported: []string{"header"},
		ResourceName:           "Sysdig MCP Server",
	}

	return RemoteSecurity{
		verifier:           verifier,
		allowedOrigins:     origins,
		corsAllowedOrigins: corsOrigins,
		metadata:           metadata,
		metadataURL:        protectedResourceMetadataURL(resourceURL),
	}
}

func (s RemoteSecurity) protect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin, hasOrigin, ok := requestOrigin(r.Header.Values("Origin"))
		if !ok {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		if hasOrigin {
			if _, allowed := s.allowedOrigins[origin]; !allowed {
				http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
				return
			}
			if isCORSPreflight(r) {
				next.ServeHTTP(w, r)
				return
			}
			applyAuthCORSHeaders(w, origin)
		}

		rawToken, ok := bearerToken(r.Header.Values("Authorization"))
		if !ok {
			s.writeUnauthorized(w, "")
			return
		}

		principal, err := s.verifier.Verify(r.Context(), rawToken)
		if err != nil {
			if errors.Is(err, infraauth.ErrInsufficientScope) {
				s.writeInsufficientScope(w)
				return
			}
			s.writeUnauthorized(w, "invalid_token")
			return
		}

		if err := validateRequestSessionOwner(r, principal); err != nil {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}

		ctx := context.WithValue(r.Context(), principalContextKey{}, principal)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s RemoteSecurity) corsOrigins() []string {
	return append([]string(nil), s.corsAllowedOrigins...)
}

func (s RemoteSecurity) sessionIDManagerResolver() server.SessionIdManagerResolver {
	return principalSessionResolver{}
}

func (s RemoteSecurity) newSessionID(ctx context.Context) (string, error) {
	principal, ok := principalFromContext(ctx)
	if !ok {
		return "", errors.New("verified principal missing from request context")
	}
	return generatePrincipalSessionID(principal)
}

func (s RemoteSecurity) writeInsufficientScope(w http.ResponseWriter) {
	challenge := fmt.Sprintf(
		`Bearer resource_metadata=%q, error="insufficient_scope", scope=%q`,
		s.metadataURL,
		strings.Join(s.metadata.ScopesSupported, " "),
	)
	w.Header().Set("WWW-Authenticate", challenge)
	http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
}

func (s RemoteSecurity) mountMetadata(mux *http.ServeMux) {
	mux.Handle(server.ProtectedResourceMetadataPath(s.metadata.Resource), server.NewProtectedResourceMetadataHandler(s.metadata))
}

func (s RemoteSecurity) writeUnauthorized(w http.ResponseWriter, authError string) {
	challenge := fmt.Sprintf(`Bearer resource_metadata=%q`, s.metadataURL)
	if authError != "" {
		challenge += fmt.Sprintf(`, error=%q`, authError)
	}
	w.Header().Set("WWW-Authenticate", challenge)
	http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
}

func applyAuthCORSHeaders(w http.ResponseWriter, origin string) {
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Add("Vary", "Origin")
	w.Header().Set("Access-Control-Expose-Headers", server.HeaderKeySessionID+", WWW-Authenticate")
}

func requestOrigin(values []string) (origin string, present bool, ok bool) {
	if len(values) == 0 {
		return "", false, true
	}
	if len(values) != 1 || strings.TrimSpace(values[0]) == "" {
		return "", true, false
	}
	return normalizeOrigin(values[0]), true, true
}

func normalizeOrigin(origin string) string {
	u, err := url.Parse(origin)
	if err != nil || !u.IsAbs() || u.Host == "" {
		return origin
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	return u.String()
}

func isCORSPreflight(r *http.Request) bool {
	return r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != ""
}

func bearerToken(values []string) (string, bool) {
	if len(values) != 1 {
		return "", false
	}

	parts := strings.Fields(values[0])
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
		return "", false
	}

	return parts[1], true
}

func protectedResourceMetadataURL(resource string) string {
	u, err := url.Parse(resource)
	if err != nil {
		return ""
	}
	u.Path = server.ProtectedResourceMetadataPath(resource)
	u.RawPath = ""
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

func principalFromContext(ctx context.Context) (infraauth.Principal, bool) {
	principal, ok := ctx.Value(principalContextKey{}).(infraauth.Principal)
	return principal, ok && principal.Issuer != "" && principal.Subject != ""
}

func principalFingerprint(principal infraauth.Principal) string {
	sum := sha256.Sum256([]byte(principal.Issuer + "\x00" + principal.Subject))
	return hex.EncodeToString(sum[:principalFingerprintSize])
}

func generatePrincipalSessionID(principal infraauth.Principal) (string, error) {
	nonce := make([]byte, sessionNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generating MCP session ID: %w", err)
	}
	return sessionIDPrefix + principalFingerprint(principal) + "-" + hex.EncodeToString(nonce), nil
}

func sessionPrincipalFingerprint(sessionID string) (string, bool) {
	if !strings.HasPrefix(sessionID, sessionIDPrefix) {
		return "", false
	}
	rest := strings.TrimPrefix(sessionID, sessionIDPrefix)
	parts := strings.SplitN(rest, "-", 2)
	if len(parts) != 2 ||
		len(parts[0]) != principalFingerprintSize*2 ||
		len(parts[1]) != sessionNonceSize*2 {
		return "", false
	}
	if _, err := hex.DecodeString(parts[0]); err != nil {
		return "", false
	}
	if _, err := hex.DecodeString(parts[1]); err != nil {
		return "", false
	}
	return parts[0], true
}

func validateSessionOwner(sessionID string, principal infraauth.Principal) error {
	fingerprint, ok := sessionPrincipalFingerprint(sessionID)
	if !ok {
		return errors.New("invalid MCP session ID")
	}
	if fingerprint != principalFingerprint(principal) {
		return errors.New("MCP session belongs to a different principal")
	}
	return nil
}

func validateRequestSessionOwner(r *http.Request, principal infraauth.Principal) error {
	if sessionID := r.Header.Get(server.HeaderKeySessionID); sessionID != "" {
		if err := validateSessionOwner(sessionID, principal); err != nil {
			return err
		}
	}
	if sessionID := r.URL.Query().Get("sessionId"); sessionID != "" {
		if err := validateSessionOwner(sessionID, principal); err != nil {
			return err
		}
	}
	return nil
}

type principalSessionResolver struct{}

func (principalSessionResolver) ResolveSessionIdManager(r *http.Request) server.SessionIdManager {
	if r == nil {
		return principalSessionManager{}
	}
	principal, ok := principalFromContext(r.Context())
	if !ok {
		return principalSessionManager{}
	}
	return principalSessionManager{fingerprint: principalFingerprint(principal)}
}

type principalSessionManager struct {
	fingerprint string
}

func (m principalSessionManager) Generate() string {
	if m.fingerprint == "" {
		return ""
	}
	nonce := make([]byte, sessionNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return ""
	}
	return sessionIDPrefix + m.fingerprint + "-" + hex.EncodeToString(nonce)
}

func (m principalSessionManager) Validate(sessionID string) (bool, error) {
	fingerprint, ok := sessionPrincipalFingerprint(sessionID)
	if !ok {
		return false, errors.New("invalid MCP session ID")
	}
	if m.fingerprint != "" && fingerprint != m.fingerprint {
		return false, errors.New("MCP session belongs to a different principal")
	}
	return false, nil
}

func (m principalSessionManager) Terminate(sessionID string) (bool, error) {
	_, err := m.Validate(sessionID)
	return false, err
}
