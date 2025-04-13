package cmd

import (
	"context"
	"fmt"

	"github.com/macmiranda/dockertags/pkg/docker"
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
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		repository := args[0]
		if debug {
			fmt.Printf("Registry: %s\n", registry)
			fmt.Printf("Repository: %s\n", repository)
		}
		client := docker.NewClient(debug)
		tags, err := client.ListTags(context.Background(), registry, repository)
		if err != nil {
			return fmt.Errorf("failed to list tags: %v", err)
		}
		for _, tag := range tags {
			fmt.Println(tag)
		}
		return nil
	},
}

func init() {
	rootCmd.Flags().StringVarP(&registry, "registry", "r", "docker.io", "Docker registry URL (e.g., docker.io, gcr.io)")
	rootCmd.Flags().BoolVar(&debug, "debug", false, "Enable debug output")
}

func Execute() error {
	return rootCmd.Execute()
}
