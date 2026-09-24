package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

const jwksRequestTimeout = 10 * time.Second

// ErrInsufficientScope distinguishes an authenticated token from one that
// lacks the authorization required by this resource.
var ErrInsufficientScope = errors.New("access token has insufficient scope")

// Principal is the authenticated identity used to bind stateful MCP sessions.
// Subject is normally the JWT sub claim. Subject-less access tokens fall back
// to a digest of the verified token, which is safe but intentionally makes the
// session valid only for that token's lifetime.
type Principal struct {
	Issuer  string
	Subject string
}

func (p Principal) valid() bool {
	return p.Issuer != "" && p.Subject != ""
}

// TokenVerifier validates an access token presented to the MCP server and
// returns the identity that owns any stateful transport session created by the
// request. Implementations must never forward the token to an upstream service.
type TokenVerifier interface {
	Verify(context.Context, string) (Principal, error)
}

// JWTVerifier validates signed JWT access tokens against a bounded remote JWKS.
// Issuer, audience, expiry, and signing algorithm checks are delegated to the
// OIDC verifier. Optional scopes are checked after cryptographic validation.
type JWTVerifier struct {
	issuer         string
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
	_ context.Context,
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

	keySet := newBoundedRemoteKeySet(
		jwksURL,
		httpClient,
		signingAlgorithms,
		defaultJWKSMinRefreshInterval,
		defaultJWKSMaxAge,
	)
	verifier := oidc.NewVerifier(issuer, keySet, &oidc.Config{
		ClientID:             audience,
		SupportedSigningAlgs: signingAlgorithms,
	})

	return &JWTVerifier{
		issuer:         issuer,
		verifier:       verifier,
		requiredScopes: slices.Clone(requiredScopes),
	}
}

func (v *JWTVerifier) Verify(ctx context.Context, rawToken string) (Principal, error) {
	token, err := v.verifier.Verify(ctx, rawToken)
	if err != nil {
		return Principal{}, fmt.Errorf("validating access token: %w", err)
	}

	var claims struct {
		Subject string          `json:"sub"`
		Scope   json.RawMessage `json:"scope"`
		SCP     json.RawMessage `json:"scp"`
	}
	if err := token.Claims(&claims); err != nil {
		return Principal{}, fmt.Errorf("decoding access token claims: %w", err)
	}

	subject := claims.Subject
	if subject == "" {
		sum := sha256.Sum256([]byte(rawToken))
		subject = "token-sha256:" + hex.EncodeToString(sum[:])
	}
	principal := Principal{Issuer: v.issuer, Subject: subject}

	grantedScopes, err := parseScopeClaim(claims.Scope)
	if err != nil {
		return Principal{}, fmt.Errorf("decoding scope claim: %w", err)
	}
	scpScopes, err := parseScopeClaim(claims.SCP)
	if err != nil {
		return Principal{}, fmt.Errorf("decoding scp claim: %w", err)
	}
	grantedScopes = append(grantedScopes, scpScopes...)

	for _, requiredScope := range v.requiredScopes {
		if !slices.Contains(grantedScopes, requiredScope) {
			return Principal{}, fmt.Errorf("%w: missing %q", ErrInsufficientScope, requiredScope)
		}
	}

	return principal, nil
}

func parseScopeClaim(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}

	var scopeString string
	if err := json.Unmarshal(raw, &scopeString); err == nil {
		return strings.Fields(scopeString), nil
	}

	var scopeList []string
	if err := json.Unmarshal(raw, &scopeList); err != nil {
		return nil, err
	}
	return scopeList, nil
}
