package cmd

import (
	"github.com/sikalabs/dummy-oidc/cmd/root"
	_ "github.com/sikalabs/dummy-oidc/cmd/server"
	_ "github.com/sikalabs/dummy-oidc/cmd/version"
	"github.com/spf13/cobra"
)

func Execute() {
	cobra.CheckErr(root.Cmd.Execute())
}
