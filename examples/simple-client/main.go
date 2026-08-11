package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

var ClientID string
var RedirectURI string
var Issuer string
var AuthorizeURL string
var TokenURL string

var (
	stateStore = make(map[string]bool)
	nonceStore = make(map[string]bool)
)

func main() {
	origin := os.Getenv("ORIGIN")
	if origin == "" {
		origin = "http://localhost:3000"
	}

	issuer := os.Getenv("ISSUER")
	if issuer == "" {
		issuer = "http://localhost:8080"
	}

	ClientID = "client"
	RedirectURI = origin + "/callback"
	Issuer = issuer
	AuthorizeURL = Issuer + "/authorize"
	TokenURL = Issuer + "/token"

	http.HandleFunc("/", handleHome)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/callback", handleCallback)

	port := "3000"
	log.Printf("Example OIDC client running on http://localhost:%s", port)
	log.Printf("Make sure the OIDC provider is running on %s", issuer)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	html := `<!DOCTYPE html>
<html>
<head>
    <title>OIDC Client Example</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            max-width: 600px;
            margin: 50px auto;
            padding: 20px;
        }
        h1 {
            color: #667eea;
        }
        .button {
            display: inline-block;
            padding: 12px 24px;
            background: #667eea;
            color: white;
            text-decoration: none;
            border-radius: 4px;
            font-weight: 500;
        }
        .button:hover {
            background: #5568d3;
        }
        .info {
            background: #f0f4ff;
            padding: 15px;
            border-radius: 4px;
            margin-top: 20px;
        }
    </style>
</head>
<body>
    <h1>OIDC Client Example</h1>
    <p>This is a simple example client that demonstrates OIDC authentication against a dummy, no-authentication provider.</p>
    <a href="/login" class="button">Login</a>
    <div class="info">
        <strong>Instructions:</strong>
        <ol>
            <li>Click "Login"</li>
            <li>Enter any email address</li>
            <li>You're logged in immediately, no verification needed</li>
            <li>You'll be redirected back here with your authentication details</li>
        </ol>
    </div>
</body>
</html>`
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	// Generate state and nonce
	state := uuid.New().String()
	nonce := uuid.New().String()

	// Store state and nonce for validation
	stateStore[state] = true
	nonceStore[nonce] = true

	// Clean up after 15 minutes
	go func() {
		time.Sleep(15 * time.Minute)
		delete(stateStore, state)
		delete(nonceStore, nonce)
	}()

	// Build authorization URL
	authURL, _ := url.Parse(AuthorizeURL)
	q := authURL.Query()
	q.Set("response_type", "code")
	q.Set("client_id", ClientID)
	q.Set("redirect_uri", RedirectURI)
	q.Set("scope", "openid email profile")
	q.Set("state", state)
	q.Set("nonce", nonce)
	authURL.RawQuery = q.Encode()

	// Redirect to OIDC provider
	http.Redirect(w, r, authURL.String(), http.StatusFound)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	// Get authorization code and state
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	// Validate state
	if !stateStore[state] {
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}
	delete(stateStore, state)

	// Exchange code for tokens
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", RedirectURI)

	resp, err := http.PostForm(TokenURL, data)
	if err != nil {
		http.Error(w, "Failed to exchange code: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		http.Error(w, "Token endpoint error: "+string(body), http.StatusInternalServerError)
		return
	}

	// Parse token response
	var tokenResp struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		http.Error(w, "Failed to parse token response: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Parse ID token (without verification for demo purposes)
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(tokenResp.IDToken, jwt.MapClaims{})
	if err != nil {
		http.Error(w, "Failed to parse ID token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	claims, _ := token.Claims.(jwt.MapClaims)

	// Display success page
	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>Login Success</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            max-width: 600px;
            margin: 50px auto;
            padding: 20px;
        }
        h1 {
            color: #48bb78;
        }
        .success {
            background: #f0fff4;
            padding: 20px;
            border-radius: 4px;
            border-left: 4px solid #48bb78;
        }
        .token-info {
            background: #f7fafc;
            padding: 15px;
            border-radius: 4px;
            margin-top: 20px;
            font-family: monospace;
            font-size: 12px;
            overflow-x: auto;
        }
        pre {
            margin: 0;
        }
        a {
            color: #667eea;
            text-decoration: none;
        }
        a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <h1>Login Successful!</h1>
    <div class="success">
        <p><strong>Email (sub):</strong> %s</p>
        <p><strong>Name:</strong> %s %s</p>
        <p><strong>Groups:</strong> %v</p>
    </div>

    <h2>ID Token Claims</h2>
    <div class="token-info">
        <pre>%s</pre>
    </div>

    <h2>Access Token</h2>
    <div class="token-info">
        <pre>%s</pre>
    </div>

    <p style="margin-top: 30px;">
        <a href="/">Back to Home</a>
    </p>
</body>
</html>`,
		claims["sub"],
		claims["given_name"],
		claims["family_name"],
		claims["groups"],
		formatJSON(claims),
		tokenResp.AccessToken,
	)

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

func formatJSON(v interface{}) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}
