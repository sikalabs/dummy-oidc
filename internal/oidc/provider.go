package oidc

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/sikalabs/dummy-oidc/internal/storage"
)

// Provider implements an OIDC provider
type Provider struct {
	issuer  string
	storage *storage.Storage
	keys    *Keys
}

// NewProvider creates a new OIDC provider
// keySeed: if empty, generates random keys; if provided, generates deterministic keys from the seed
func NewProvider(issuer string, storage *storage.Storage, keySeed string) (*Provider, error) {
	keys, err := NewKeys(keySeed)
	if err != nil {
		return nil, fmt.Errorf("failed to generate keys: %w", err)
	}

	return &Provider{
		issuer:  issuer,
		storage: storage,
		keys:    keys,
	}, nil
}

// parseEmail derives given name, family name and group (email domain) from an email address.
// "xxx.yyy@domain.com" yields given name "xxx", family name "yyy", group "domain.com".
// "xxx@domain.com" yields given name "xxx", family name "xxx", group "domain.com".
func parseEmail(email string) (givenName, familyName, group string) {
	local, domain, _ := strings.Cut(email, "@")

	if before, after, found := strings.Cut(local, "."); found {
		return before, after, domain
	}

	return local, local, domain
}

// Discovery returns the OIDC discovery document
func (p *Provider) Discovery() map[string]interface{} {
	return map[string]interface{}{
		"issuer":                 p.issuer,
		"authorization_endpoint": p.issuer + "/authorize",
		"token_endpoint":         p.issuer + "/token",
		"userinfo_endpoint":      p.issuer + "/userinfo",
		"jwks_uri":               p.issuer + "/.well-known/jwks.json",
		"response_types_supported": []string{
			"code",
		},
		"subject_types_supported": []string{
			"public",
		},
		"id_token_signing_alg_values_supported": []string{
			"RS256",
		},
		"scopes_supported": []string{
			"openid",
			"email",
			"profile",
		},
		"claims_supported": []string{
			"sub",
			"email",
			"email_verified",
			"given_name",
			"family_name",
			"groups",
			"iss",
			"aud",
			"exp",
			"iat",
			"nonce",
		},
		"grant_types_supported": []string{
			"authorization_code",
		},
	}
}

// JWKS returns the JSON Web Key Set
func (p *Provider) JWKS() map[string]interface{} {
	return p.keys.GetJWKS()
}

// HandleAuthorize handles the authorization request
func (p *Provider) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters
	query := r.URL.Query()
	responseType := query.Get("response_type")
	clientID := query.Get("client_id")
	redirectURI := query.Get("redirect_uri")
	state := query.Get("state")
	nonce := query.Get("nonce")
	scope := query.Get("scope")

	// Validate parameters
	if responseType != "code" {
		http.Error(w, "unsupported response_type", http.StatusBadRequest)
		return
	}

	if clientID == "" || redirectURI == "" {
		http.Error(w, "missing required parameters", http.StatusBadRequest)
		return
	}

	// Check if openid scope is present
	if !strings.Contains(scope, "openid") {
		http.Error(w, "openid scope is required", http.StatusBadRequest)
		return
	}

	// Show email login form
	p.showLoginForm(w, state, redirectURI, nonce)
}

// showLoginForm displays the email login form
func (p *Provider) showLoginForm(w http.ResponseWriter, state, redirectURI, nonce string) {
	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            background: repeating-linear-gradient(135deg, #f5a623, #f5a623 20px, #d9822b 20px, #d9822b 40px);
        }
        .container {
            background: white;
            padding: 2rem;
            border-radius: 8px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            width: 100%%;
            max-width: 400px;
        }
        .warning-banner {
            margin: -2rem -2rem 1.5rem -2rem;
            padding: 10px 2rem;
            background: #d9302f;
            color: white;
            font-size: 12px;
            font-weight: 700;
            letter-spacing: 0.05em;
            text-transform: uppercase;
            text-align: center;
            border-radius: 8px 8px 0 0;
        }
        h1 {
            margin: 0 0 1.5rem 0;
            color: #333;
            font-size: 24px;
        }
        input[type="email"] {
            width: 100%%;
            padding: 12px;
            margin-bottom: 1rem;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 16px;
            box-sizing: border-box;
        }
        button {
            width: 100%%;
            padding: 12px;
            background: #d9822b;
            color: white;
            border: none;
            border-radius: 4px;
            font-size: 16px;
            font-weight: 500;
            cursor: pointer;
        }
        button:hover {
            background: #c26f1f;
        }
        .info {
            margin-top: 1rem;
            padding: 12px;
            background: #fff4e5;
            border-radius: 4px;
            font-size: 14px;
            color: #7a4a00;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="warning-banner">&#9888; Development only &mdash; no authentication</div>
        <h1>Sign in</h1>
        <form method="POST" action="/login">
            <input type="email" name="email" placeholder="Enter your email" required autofocus autocomplete="off">
            <input type="hidden" name="state" value="%s">
            <input type="hidden" name="redirect_uri" value="%s">
            <input type="hidden" name="nonce" value="%s">
            <button type="submit">Login</button>
        </form>
        <div class="info">
            This is a dummy provider. No password or verification is required &mdash; any email logs you in immediately.
        </div>
    </div>
</body>
</html>`, state, redirectURI, nonce)

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

// HandleLogin handles the email submission and logs the user in immediately
func (p *Provider) HandleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse form data
	if err := r.ParseForm(); err != nil {
		http.Error(w, "failed to parse form", http.StatusBadRequest)
		return
	}

	email := r.FormValue("email")
	state := r.FormValue("state")
	redirectURI := r.FormValue("redirect_uri")
	nonce := r.FormValue("nonce")

	if email == "" || redirectURI == "" {
		http.Error(w, "missing required parameters", http.StatusBadRequest)
		return
	}

	if !strings.Contains(email, "@") {
		http.Error(w, "invalid email", http.StatusBadRequest)
		return
	}

	// Create authorization code immediately, no verification step
	authCode, err := p.storage.CreateAuthorizationCode(email, redirectURI, nonce)
	if err != nil {
		http.Error(w, "failed to create authorization code", http.StatusInternalServerError)
		return
	}

	// Redirect back to client with authorization code
	redirectURL, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}
	q := redirectURL.Query()
	q.Set("code", authCode.Code)
	if state != "" {
		q.Set("state", state)
	}
	redirectURL.RawQuery = q.Encode()

	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

// HandleToken handles the token exchange
func (p *Provider) HandleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse form data
	if err := r.ParseForm(); err != nil {
		http.Error(w, "failed to parse form", http.StatusBadRequest)
		return
	}

	grantType := r.FormValue("grant_type")
	code := r.FormValue("code")
	redirectURI := r.FormValue("redirect_uri")

	if grantType != "authorization_code" {
		p.tokenError(w, "unsupported_grant_type", "only authorization_code is supported")
		return
	}

	if code == "" {
		p.tokenError(w, "invalid_request", "code is required")
		return
	}

	// Get and validate authorization code
	authCode, exists := p.storage.GetAuthorizationCode(code)
	if !exists {
		p.tokenError(w, "invalid_grant", "invalid or expired authorization code")
		return
	}

	// Validate redirect URI
	if authCode.RedirectURI != redirectURI {
		p.tokenError(w, "invalid_grant", "redirect_uri mismatch")
		return
	}

	// Generate tokens
	now := time.Now()
	exp := now.Add(1 * time.Hour)
	givenName, familyName, group := parseEmail(authCode.Email)

	// Create ID token
	idTokenClaims := jwt.MapClaims{
		"iss":            p.issuer,
		"sub":            authCode.Email,
		"aud":            "client", // In production, use actual client_id
		"exp":            exp.Unix(),
		"iat":            now.Unix(),
		"email":          authCode.Email,
		"email_verified": true,
		"given_name":     givenName,
		"family_name":    familyName,
		"groups":         []string{group},
	}

	if authCode.Nonce != "" {
		idTokenClaims["nonce"] = authCode.Nonce
	}

	idToken := jwt.NewWithClaims(jwt.SigningMethodRS256, idTokenClaims)
	idToken.Header["kid"] = p.keys.GetKID()

	idTokenString, err := idToken.SignedString(p.keys.GetPrivateKey())
	if err != nil {
		http.Error(w, "failed to sign token", http.StatusInternalServerError)
		return
	}

	// Create access token
	accessTokenClaims := jwt.MapClaims{
		"iss":            p.issuer,
		"sub":            authCode.Email,
		"aud":            "client",
		"exp":            exp.Unix(),
		"iat":            now.Unix(),
		"email":          authCode.Email,
		"email_verified": true,
		"given_name":     givenName,
		"family_name":    familyName,
		"groups":         []string{group},
		"jti":            uuid.New().String(),
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodRS256, accessTokenClaims)
	accessToken.Header["kid"] = p.keys.GetKID()

	accessTokenString, err := accessToken.SignedString(p.keys.GetPrivateKey())
	if err != nil {
		http.Error(w, "failed to sign token", http.StatusInternalServerError)
		return
	}

	// Return tokens
	response := map[string]interface{}{
		"access_token": accessTokenString,
		"token_type":   "Bearer",
		"expires_in":   3600,
		"id_token":     idTokenString,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// HandleUserInfo handles the userinfo endpoint
func (p *Provider) HandleUserInfo(w http.ResponseWriter, r *http.Request) {
	// Extract bearer token
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, "missing or invalid authorization header", http.StatusUnauthorized)
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	// Parse and validate token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return &p.keys.GetPrivateKey().PublicKey, nil
	})

	if err != nil || !token.Valid {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		http.Error(w, "invalid token claims", http.StatusUnauthorized)
		return
	}

	// Return user info
	response := map[string]interface{}{
		"sub":            claims["sub"],
		"email":          claims["email"],
		"email_verified": claims["email_verified"],
		"given_name":     claims["given_name"],
		"family_name":    claims["family_name"],
		"groups":         claims["groups"],
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// tokenError returns an OAuth2 error response
func (p *Provider) tokenError(w http.ResponseWriter, errorCode, errorDescription string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(map[string]string{
		"error":             errorCode,
		"error_description": errorDescription,
	})
}
