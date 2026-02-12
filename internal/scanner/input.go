package scanner

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
)

func LoadInput(path string, includeFailed bool) ([]string, error) {
	if strings.HasSuffix(strings.ToLower(path), ".json") {
		return loadJSON(path, includeFailed)
	}
	return loadText(path)
}

func loadText(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var ips []string
	var skipped int
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ip := line
		// Strip optional :port suffix
		if host, _, err := net.SplitHostPort(line); err == nil {
			ip = host
		}
		if net.ParseIP(ip) == nil {
			skipped++
			continue
		}
		ips = append(ips, ip)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if skipped > 0 {
		fmt.Fprintf(os.Stderr, "input: skipped %d invalid entries\n", skipped)
	}
	return ips, nil
}

func loadJSON(path string, includeFailed bool) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var report Report
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, err
	}
	ips := make([]string, 0, len(report.Passed)+len(report.Failed))
	for _, rec := range report.Passed {
		ips = append(ips, rec.IP)
	}
	if includeFailed {
		for _, rec := range report.Failed {
			ips = append(ips, rec.IP)
		}
	}
	return ips, nil
}
