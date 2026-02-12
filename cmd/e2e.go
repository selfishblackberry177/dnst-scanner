package main

import "github.com/spf13/cobra"

var e2eTimeout int

var e2eCmd = &cobra.Command{
	Use:   "e2e",
	Short: "End-to-end tunnel connectivity test",
}

func init() {
	e2eCmd.PersistentFlags().IntVar(&e2eTimeout, "timeout", 5, "timeout per resolver in seconds")
	rootCmd.AddCommand(e2eCmd)
}
