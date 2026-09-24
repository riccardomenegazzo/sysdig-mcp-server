package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/coreos/go-oidc/v3/oidc"
)

const (
	jwksRequestTimeout      = 10 * time.Second
	jwksMinRefreshInterval  = 30 * time.Second
	jwksMaxKeyAge           = 15 * time.Minute
	maxJWKSResponseBodySize = 1 << 20
)

// ErrInsufficientScope distinguishes an authenticated token from one that
// lacks the authorization required by this resource.
var ErrInsufficientScope = errors.New("access token has insufficient scope")

// Principal is the verified identity that owns an MCP request/session.
type Principal struct {
	Issuer  string
	Subject string
}

// TokenVerifier validates an access token presented to the MCP server.
// Implementations must never forward the token to an upstream service.
type TokenVerifier interface {
	Verify(context.Context, string) (Principal, error)
}

// JWTVerifier validates signed JWT access tokens against a remote JWKS.
// Issuer, audience, expiry, and signing algorithm checks are delegated to the
// OIDC verifier. Optional scopes are checked after cryptographic validation.
type JWTVerifier struct {
	verifier       *oidc.IDTokenVerifier
	requiredScopes []string
}

func NewJWTVerifier(
	ctx context.Context,
	issuer string,
	audience string,
	jwksURL string,
	signingAlgorithms []string,
	requiredScopes []string,
) *JWTVerifier {
	return NewJWTVerifierWithHTTPClient(
		ctx,
		issuer,
		audience,
		jwksURL,
		signingAlgorithms,
		requiredScopes,
		nil,
	)
}

func NewJWTVerifierWithHTTPClient(
	ctx context.Context,
	issuer string,
	audience string,
	jwksURL string,
	signingAlgorithms []string,
	requiredScopes []string,
	httpClient *http.Client,
) *JWTVerifier {
	if httpClient == nil {
		httpClient = &http.Client{}
	} else {
		clone := *httpClient
		httpClient = &clone
	}
	if httpClient.Timeout == 0 {
		httpClient.Timeout = jwksRequestTimeout
	}

	keySet := newRefreshingRemoteKeySet(
		httpClient,
		jwksURL,
		signingAlgorithms,
		jwksMinRefreshInterval,
		jwksMaxKeyAge,
	)
	verifier := oidc.NewVerifier(issuer, keySet, &oidc.Config{
		ClientID:             audience,
		SupportedSigningAlgs: signingAlgorithms,
	})

	return &JWTVerifier{
		verifier:       verifier,
		requiredScopes: slices.Clone(requiredScopes),
	}
}

func (v *JWTVerifier) Verify(ctx context.Context, rawToken string) (Principal, error) {
	token, err := v.verifier.Verify(ctx, rawToken)
	if err != nil {
		return Principal{}, fmt.Errorf("validating access token: %w", err)
	}
	if token.Subject == "" {
		return Principal{}, errors.New("validating access token: missing sub claim")
	}

	principal := Principal{Issuer: token.Issuer, Subject: token.Subject}
	if len(v.requiredScopes) == 0 {
		return principal, nil
	}

	var claims struct {
		Scope json.RawMessage `json:"scope"`
		SCP   json.RawMessage `json:"scp"`
	}
	if err := token.Claims(&claims); err != nil {
		return Principal{}, fmt.Errorf("decoding access token claims: %w", err)
	}

	grantedScopes, err := parseScopeClaim("scope", claims.Scope)
	if err != nil {
		return Principal{}, err
	}
	scpScopes, err := parseScopeClaim("scp", claims.SCP)
	if err != nil {
		return Principal{}, err
	}
	grantedScopes = append(grantedScopes, scpScopes...)

	for _, requiredScope := range v.requiredScopes {
		if !slices.Contains(grantedScopes, requiredScope) {
			return Principal{}, fmt.Errorf("%w: missing %q", ErrInsufficientScope, requiredScope)
		}
	}

	return principal, nil
}

func parseScopeClaim(name string, raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}

	var scopeString string
	if err := json.Unmarshal(raw, &scopeString); err == nil {
		return strings.Fields(scopeString), nil
	}

	var scopeList []string
	if err := json.Unmarshal(raw, &scopeList); err == nil {
		return scopeList, nil
	}

	return nil, fmt.Errorf("decoding %s claim: expected string or string array", name)
}

// refreshingRemoteKeySet bounds both sides of JWKS caching: unknown key IDs can
// trigger at most one refresh per minimum interval, while cached keys are never
// trusted beyond maxKeyAge without a successful refresh.
type refreshingRemoteKeySet struct {
	client             *http.Client
	jwksURL            string
	signingAlgorithms  []jose.SignatureAlgorithm
	minRefreshInterval time.Duration
	maxKeyAge          time.Duration

	mu                 sync.Mutex
	keys               []jose.JSONWebKey
	fetchedAt          time.Time
	lastRefreshAttempt time.Time
}

func newRefreshingRemoteKeySet(
	client *http.Client,
	jwksURL string,
	signingAlgorithms []string,
	minRefreshInterval time.Duration,
	maxKeyAge time.Duration,
) *refreshingRemoteKeySet {
	algs := make([]jose.SignatureAlgorithm, 0, len(signingAlgorithms))
	for _, algorithm := range signingAlgorithms {
		algs = append(algs, jose.SignatureAlgorithm(algorithm))
	}
	return &refreshingRemoteKeySet{
		client:             client,
		jwksURL:            jwksURL,
		signingAlgorithms:  algs,
		minRefreshInterval: minRefreshInterval,
		maxKeyAge:          maxKeyAge,
	}
}

func (k *refreshingRemoteKeySet) VerifySignature(ctx context.Context, rawToken string) ([]byte, error) {
	jws, err := jose.ParseSigned(rawToken, k.signingAlgorithms)
	if err != nil {
		return nil, fmt.Errorf("parsing jwt: %w", err)
	}
	if len(jws.Signatures) != 1 {
		return nil, errors.New("jwt must contain exactly one signature")
	}
	keyID := jws.Signatures[0].Header.KeyID

	k.mu.Lock()
	defer k.mu.Unlock()

	now := time.Now()
	if len(k.keys) == 0 || k.fetchedAt.IsZero() || now.Sub(k.fetchedAt) >= k.maxKeyAge {
		if err := k.refreshLocked(ctx, now); err != nil {
			return nil, err
		}
	}

	if payload, ok := verifyWithJWKS(jws, keyID, k.keys); ok {
		return payload, nil
	}

	// A miss can indicate normal key rotation, but refreshing on every random
	// kid lets unauthenticated traffic exhaust the IdP. Rate-limit miss-driven
	// refreshes while maxKeyAge still guarantees eventual key eviction.
	if now.Sub(k.lastRefreshAttempt) >= k.minRefreshInterval {
		if err := k.refreshLocked(ctx, now); err != nil {
			return nil, err
		}
		if payload, ok := verifyWithJWKS(jws, keyID, k.keys); ok {
			return payload, nil
		}
	}

	return nil, errors.New("failed to verify access token signature")
}

func (k *refreshingRemoteKeySet) refreshLocked(ctx context.Context, now time.Time) error {
	k.lastRefreshAttempt = now

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.jwksURL, nil)
	if err != nil {
		return fmt.Errorf("creating JWKS request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Cache-Control", "no-cache")

	resp, err := k.client.Do(req)
	if err != nil {
		return fmt.Errorf("fetching JWKS: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSResponseBodySize+1))
	if err != nil {
		return fmt.Errorf("reading JWKS response: %w", err)
	}
	if len(body) > maxJWKSResponseBodySize {
		return fmt.Errorf("JWKS response exceeds %d bytes", maxJWKSResponseBodySize)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetching JWKS: unexpected HTTP status %s", resp.Status)
	}

	var keySet jose.JSONWebKeySet
	if err := json.Unmarshal(body, &keySet); err != nil {
		return fmt.Errorf("decoding JWKS: %w", err)
	}
	if len(keySet.Keys) == 0 {
		return errors.New("decoding JWKS: key set is empty")
	}

	k.keys = slices.Clone(keySet.Keys)
	k.fetchedAt = now
	return nil
}

func verifyWithJWKS(jws *jose.JSONWebSignature, keyID string, keys []jose.JSONWebKey) ([]byte, bool) {
	for i := range keys {
		key := &keys[i]
		if keyID != "" && key.KeyID != keyID {
			continue
		}
		payload, err := jws.Verify(key)
		if err == nil {
			return payload, true
		}
	}
	return nil, false
}
