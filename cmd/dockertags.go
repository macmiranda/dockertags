package cmd

import (
	"github.com/spf13/cobra"
)

var (
	registry string
	debug    bool
)

var rootCmd = &cobra.Command{
	Use:   "dockertags",
	Short: "A tool to manage Docker tags",
	Long:  `A tool to manage Docker tags and their metadata`,
}

func init() {
	rootCmd.Flags().StringVarP(&registry, "registry", "r", "", "Docker registry URL (e.g., docker.io, gcr.io)")
	rootCmd.Flags().BoolVar(&debug, "debug", false, "Enable debug output")
	rootCmd.MarkFlagRequired("registry")
}

func Execute() error {
	return rootCmd.Execute()
}
