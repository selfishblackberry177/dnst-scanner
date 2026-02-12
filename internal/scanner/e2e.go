package scanner

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"
)

func PortPool(base, count int) chan int {
	ch := make(chan int, count)
	for i := 0; i < count; i++ {
		ch <- base + i
	}
	return ch
}

func DnsttCheck(domain, pubkey, testURL string, ports chan int) CheckFunc {
	return func(ip string, timeout time.Duration) (bool, Metrics) {
		port := <-ports
		defer func() { ports <- port }()

		start := time.Now()

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		cmd := exec.CommandContext(ctx, "dnstt-client",
			"-udp", ip+":53",
			"-pubkey", pubkey,
			domain,
			fmt.Sprintf("127.0.0.1:%d", port))
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
		if err := cmd.Start(); err != nil {
			return false, nil
		}
		defer func() {
			cmd.Process.Kill()
			cmd.Wait()
		}()

		select {
		case <-time.After(2 * time.Second):
		case <-ctx.Done():
			return false, nil
		}

		if !testSOCKS(ctx, port, testURL) {
			return false, nil
		}
		ms := roundMs(float64(time.Since(start).Microseconds()) / 1000.0)
		return true, Metrics{"e2e_ms": ms}
	}
}

func SlipstreamCheck(domain, certPath, testURL string, ports chan int) CheckFunc {
	return func(ip string, timeout time.Duration) (bool, Metrics) {
		port := <-ports
		defer func() { ports <- port }()

		start := time.Now()

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		args := []string{
			"-d", domain,
			"-r", ip + ":53",
			"-l", fmt.Sprintf("%d", port),
		}
		if certPath != "" {
			args = append(args, "--cert", certPath)
		}
		cmd := exec.CommandContext(ctx, "slipstream-client", args...)
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
		if err := cmd.Start(); err != nil {
			return false, nil
		}
		defer func() {
			cmd.Process.Kill()
			cmd.Wait()
		}()

		select {
		case <-time.After(2 * time.Second):
		case <-ctx.Done():
			return false, nil
		}

		if !testSOCKS(ctx, port, testURL) {
			return false, nil
		}
		ms := roundMs(float64(time.Since(start).Microseconds()) / 1000.0)
		return true, Metrics{"e2e_ms": ms}
	}
}

func testSOCKS(ctx context.Context, port int, testURL string) bool {
	cmd := exec.CommandContext(ctx, "curl",
		"-x", fmt.Sprintf("socks5h://127.0.0.1:%d", port),
		"-s", "-o", "/dev/null", "-w", "%{http_code}",
		testURL)
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(output)) == "200"
}
