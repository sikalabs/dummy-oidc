package server

import (
	"log"
	"os"
	"strings"

	"github.com/sikalabs/dummy-oidc/cmd/root"
	"github.com/sikalabs/dummy-oidc/internal/server"
	"github.com/spf13/cobra"
)

var (
	port    string
	issuer  string
	keySeed string
	emails  []string
)

var Cmd = &cobra.Command{
	Use:   "server",
	Short: "Start the OIDC server",
	Long: `Start the OIDC server with dummy, no-authentication login.

The server provides a complete OIDC provider that logs users in automatically.
When users attempt to log in, they are shown a form with a single email field.
Submitting the form immediately completes the authentication flow with no
password or verification step of any kind. The email's local part is used to
derive given_name/family_name ("first.last@x" -> "first"/"last", "first@x" ->
"first"/"first"), and the email domain becomes the "groups" claim.

Environment variables:
  PORT     - Server port (default: 8080)
  ISSUER   - OIDC issuer URL (default: http://localhost:8080)
  KEY_SEED - Seed string for deterministic RSA key generation (optional)
  EMAILS   - Comma-separated emails offered as one-click login buttons (optional)

Quick-login emails can also be passed with --email, either comma-separated
(--email a@x.com,b@x.com) or repeated (--email a@x.com --email b@x.com).
The login form still accepts any other email.

If KEY_SEED is not provided, a random RSA key will be generated on each startup.`,
	Run: runServer,
}

func init() {
	root.Cmd.AddCommand(Cmd)

	Cmd.Flags().StringVarP(&port, "port", "p", getEnv("PORT", "8080"), "Server port")
	Cmd.Flags().StringVarP(&issuer, "issuer", "i", getEnv("ISSUER", "http://localhost:8080"), "OIDC issuer URL")
	Cmd.Flags().StringSliceVarP(&emails, "email", "e", splitList(os.Getenv("EMAILS")), "Email offered as a one-click login button (comma-separated or repeatable)")
	Cmd.Flags().StringVarP(&keySeed, "key-seed", "k", getEnv("KEY_SEED", ""), "Seed string for deterministic RSA key generation (empty = random)")
}

func runServer(cmd *cobra.Command, args []string) {
	config := &server.Config{
		Port:        port,
		Issuer:      issuer,
		KeySeed:     keySeed,
		QuickEmails: splitList(strings.Join(emails, ",")),
	}

	srv, err := server.NewServer(config)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	if err := srv.Start(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// splitList splits a comma-separated string, trimming whitespace and dropping empty items
func splitList(s string) []string {
	var out []string
	for _, item := range strings.Split(s, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}
