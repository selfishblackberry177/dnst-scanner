package main

import (
	"fmt"
	"os"
	"time"

	"github.com/net2share/dnst-scanner/internal/scanner"
	"github.com/spf13/cobra"
)

var (
	inputFile        string
	outputFile       string
	includeFailed    bool
	workers          int
	timeout          int
	count            int
	ignoreRcodeNames []string
)

var rootCmd = &cobra.Command{
	Use:               "dnst-scanner",
	Short:             "DNS tunnel scanner - test resolvers for tunneling viability",
	CompletionOptions: cobra.CompletionOptions{DisableDefaultCmd: true},
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&inputFile, "input", "i", "", "input file (text or JSON)")
	rootCmd.PersistentFlags().StringVarP(&outputFile, "output", "o", "", "output JSON file")
	rootCmd.PersistentFlags().BoolVar(&includeFailed, "include-failed", false, "also scan failed IPs from JSON input")
	rootCmd.PersistentFlags().IntVar(&workers, "workers", 50, "concurrent workers")
	rootCmd.PersistentFlags().IntVarP(&timeout, "timeout", "t", 3, "timeout per attempt in seconds")
	rootCmd.PersistentFlags().IntVarP(&count, "count", "c", 3, "number of attempts per IP for ping/resolve checks")
	rootCmd.PersistentFlags().StringSliceVar(&ignoreRcodeNames, "ignore-rcode", nil, "DNS rcodes to ignore, e.g. nxdomain, servfail, refused, formerr (repeatable)")
	rootCmd.MarkPersistentFlagRequired("input")
	rootCmd.MarkPersistentFlagRequired("output")
	rootCmd.SilenceUsage = true
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func parseIgnoreRcodes() ([]int, error) {
	if len(ignoreRcodeNames) == 0 {
		return nil, nil
	}
	codes := make([]int, 0, len(ignoreRcodeNames))
	for _, name := range ignoreRcodeNames {
		code, err := scanner.ParseRcode(name)
		if err != nil {
			return nil, err
		}
		codes = append(codes, code)
	}
	return codes, nil
}

func loadInput() ([]string, error) {
	ips, err := scanner.LoadInput(inputFile, includeFailed)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no resolvers found in %s", inputFile)
	}
	return ips, nil
}

func writeReport(mode string, results []scanner.Result, elapsed time.Duration, sortBy string) error {
	// Sort passed results by metric before writing
	passed := make([]scanner.Result, 0, len(results))
	failed := make([]scanner.Result, 0)
	for _, r := range results {
		if r.OK {
			passed = append(passed, r)
		} else {
			failed = append(failed, r)
		}
	}
	if sortBy != "" {
		scanner.SortByMetric(passed, sortBy)
	}
	sorted := append(passed, failed...)

	if err := scanner.WriteReport(sorted, outputFile); err != nil {
		return err
	}
	scanner.PrintStats(mode, results, elapsed)
	return nil
}

func isTTY() bool {
	fi, err := os.Stderr.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func newProgress(label string) scanner.ProgressFunc {
	if !isTTY() {
		return nil
	}
	return func(done, total, passed, failed int) {
		pct := done * 100 / total
		fmt.Fprintf(os.Stderr, "\r\033[2K%s: %d/%d [%d%%] | %d pass | %d fail", label, done, total, pct, passed, failed)
		if done == total {
			fmt.Fprint(os.Stderr, "\r\033[2K")
		}
	}
}

func newProgressFactory() scanner.ProgressFactory {
	if !isTTY() {
		return nil
	}
	return func(stepName string) scanner.ProgressFunc {
		return newProgress(stepName)
	}
}
