package scanner

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const maxConsecFail = 3

var pingAvgRegex = regexp.MustCompile(`= [\d.]+/([\d.]+)/`)

func parsePingAvg(output string) float64 {
	m := pingAvgRegex.FindStringSubmatch(output)
	if len(m) < 2 {
		return 0
	}
	v, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0
	}
	return v
}

func PingCheck(count int) CheckFunc {
	return func(ip string, timeout time.Duration) (bool, Metrics) {
		secs := int(timeout.Seconds())
		if secs < 1 {
			secs = 1
		}
		deadline := count + secs
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(deadline+2)*time.Second)
		defer cancel()

		cmd := exec.CommandContext(ctx, "ping",
			"-c", fmt.Sprintf("%d", count),
			"-W", fmt.Sprintf("%d", secs),
			"-w", fmt.Sprintf("%d", deadline),
			ip)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return false, nil
		}
		avg := parsePingAvg(string(out))
		return true, Metrics{"ping_ms": avg}
	}
}

func ResolveCheck(domain string, count int, ignoreRcodes []int) CheckFunc {
	return func(ip string, timeout time.Duration) (bool, Metrics) {
		var successes []float64
		var consecFail int

		for i := 0; i < count; i++ {
			start := time.Now()
			if QueryA(ip, domain, timeout, ignoreRcodes) {
				ms := float64(time.Since(start).Microseconds()) / 1000.0
				successes = append(successes, ms)
				consecFail = 0
			} else {
				consecFail++
				if consecFail >= maxConsecFail {
					return false, nil
				}
			}
		}

		if len(successes) == 0 {
			return false, nil
		}

		var sum float64
		for _, v := range successes {
			sum += v
		}
		return true, Metrics{"resolve_ms": roundMs(sum / float64(len(successes)))}
	}
}

func TunnelCheck(domain string, count int, ignoreRcodes []int) CheckFunc {
	return func(ip string, timeout time.Duration) (bool, Metrics) {
		// Step 1: Discover NS delegation from parent authoritative server (once)
		hosts, ok := DiscoverNS(ip, domain, timeout, ignoreRcodes)
		if !ok || len(hosts) == 0 {
			return false, nil
		}
		nsHost := strings.TrimRight(hosts[0], ".")

		// Step 2: Verify resolver can resolve the NS hostname (repeated)
		var successes []float64
		var consecFail int

		for i := 0; i < count; i++ {
			start := time.Now()
			if QueryA(ip, nsHost, timeout, ignoreRcodes) {
				ms := float64(time.Since(start).Microseconds()) / 1000.0
				successes = append(successes, ms)
				consecFail = 0
			} else {
				consecFail++
				if consecFail >= maxConsecFail {
					return false, nil
				}
			}
		}

		if len(successes) == 0 {
			return false, nil
		}

		var sum float64
		for _, v := range successes {
			sum += v
		}
		return true, Metrics{"resolve_ms": roundMs(sum / float64(len(successes)))}
	}
}
