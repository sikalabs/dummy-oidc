package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/sikalabs/dummy-oidc/internal/oidc"
	"github.com/sikalabs/dummy-oidc/internal/storage"
)

// Config holds the server configuration
type Config struct {
	Port    string
	Issuer  string
	KeySeed string
}

// Server represents the HTTP server
type Server struct {
	config   *Config
	provider *oidc.Provider
	router   *chi.Mux
}

// NewServer creates a new HTTP server
func NewServer(config *Config) (*Server, error) {
	// Create services
	store := storage.NewStorage()

	// Create OIDC provider
	provider, err := oidc.NewProvider(config.Issuer, store, config.KeySeed)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC provider: %w", err)
	}

	// Create server
	s := &Server{
		config:   config,
		provider: provider,
		router:   chi.NewRouter(),
	}

	// Setup routes
	s.setupRoutes()

	return s, nil
}

// setupRoutes configures all HTTP routes
func (s *Server) setupRoutes() {
	// Middleware
	s.router.Use(middleware.Logger)
	s.router.Use(middleware.Recoverer)
	s.router.Use(middleware.RealIP)

	// OIDC Discovery
	s.router.Get("/.well-known/openid-configuration", s.handleDiscovery)
	s.router.Get("/.well-known/jwks.json", s.handleJWKS)

	// OIDC Endpoints
	s.router.Get("/authorize", s.provider.HandleAuthorize)
	s.router.Post("/token", s.provider.HandleToken)
	s.router.Get("/userinfo", s.provider.HandleUserInfo)
	s.router.Post("/userinfo", s.provider.HandleUserInfo)

	// Username login flow (no authentication, logs in automatically)
	s.router.Post("/login", s.provider.HandleLogin)

	// Health check
	s.router.Get("/health", s.handleHealth)

	// Homepage
	s.router.Get("/", s.handleHome)
}

// handleDiscovery returns the OIDC discovery document
func (s *Server) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.provider.Discovery())
}

// handleJWKS returns the JSON Web Key Set
func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.provider.JWKS())
}

// handleHealth returns server health status
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "ok",
	})
}

// handleHome returns the homepage
func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>Dummy OIDC Provider</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 2rem;
            line-height: 1.6;
            color: #333;
            background: #fffaf0;
        }
        .warning-banner {
            background: #d9302f;
            color: white;
            font-weight: 700;
            letter-spacing: 0.05em;
            text-transform: uppercase;
            text-align: center;
            padding: 12px;
            border-radius: 4px;
            margin-bottom: 1.5rem;
        }
        h1 {
            color: #d9822b;
        }
        .endpoint {
            background: #f7fafc;
            padding: 1rem;
            margin: 0.5rem 0;
            border-radius: 4px;
            border-left: 4px solid #d9822b;
        }
        code {
            background: #e2e8f0;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Monaco', 'Menlo', monospace;
            font-size: 14px;
        }
        a {
            color: #d9822b;
            text-decoration: none;
        }
        a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="warning-banner">&#9888; Development only &mdash; no authentication</div>
    <h1>Dummy OIDC Provider</h1>
    <p>This is an OIDC provider with no authentication. Users only enter an email address and are logged in immediately.</p>

    <h2>Endpoints</h2>

    <div class="endpoint">
        <strong>Discovery Document:</strong><br>
        <a href="/.well-known/openid-configuration"><code>GET /.well-known/openid-configuration</code></a>
    </div>

    <div class="endpoint">
        <strong>JWKS:</strong><br>
        <a href="/.well-known/jwks.json"><code>GET /.well-known/jwks.json</code></a>
    </div>

    <div class="endpoint">
        <strong>Authorization:</strong><br>
        <code>GET /authorize</code>
    </div>

    <div class="endpoint">
        <strong>Token:</strong><br>
        <code>POST /token</code>
    </div>

    <div class="endpoint">
        <strong>UserInfo:</strong><br>
        <code>GET /userinfo</code>
    </div>

    <h2>How it works</h2>
    <ol>
        <li>User initiates OIDC login flow from your application</li>
        <li>User enters any email address &mdash; no password, no verification</li>
        <li>Authorization code is returned to your application immediately</li>
        <li>Your application exchanges the code for tokens</li>
        <li>The ID token contains <code>sub</code>, <code>email</code>, <code>given_name</code>, <code>family_name</code> and <code>groups</code> (the email domain)</li>
    </ol>

    <h2>Configuration</h2>
    <p>Issuer: <code>%s</code></p>
</body>
</html>`, s.config.Issuer)

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

// Start starts the HTTP server
func (s *Server) Start() error {
	addr := ":" + s.config.Port
	log.Printf("Starting OIDC provider on %s", addr)
	log.Printf("Issuer: %s", s.config.Issuer)
	log.Printf("Discovery: %s/.well-known/openid-configuration", s.config.Issuer)

	return http.ListenAndServe(addr, s.router)
}
