package root

import (
	"github.com/sikalabs/dummy-oidc/version"
	"github.com/spf13/cobra"
)

var Cmd = &cobra.Command{
	Use:   "dummy-oidc",
	Short: "dummy-oidc, " + version.Version,
}
