# dnst-scanner

A CLI tool to scan and evaluate DNS resolvers for tunneling viability. Supports basic liveness checks, censorship detection, NS delegation verification, and end-to-end tunnel connectivity tests through [DNSTT](https://www.bamsoftware.com/software/dnstt/) and [Slipstream](https://github.com/Mygod/slipstream-rust).

## Build

```bash
go build -o scanner ./cmd
```

## Commands

### ping

Check IP reachability via ICMP ping. Sends `--count` pings with `--timeout` seconds wait each, reports average RTT.

```bash
./scanner ping -i resolvers.txt -o result.json
./scanner ping -i resolvers.txt -o result.json -c 5 -t 2
```

### resolve

Test if resolvers can resolve a given domain. Queries `--count` times and reports average resolve time.

```bash
./scanner resolve -i resolvers.txt -o result.json --domain google.com
```

### resolve tunnel

Test NS delegation and glue record resolution for a tunnel domain. For each attempt it queries the NS record, then resolves the returned NS hostname via an A query to verify the full DNS chain. Runs `--count` times and reports the average.

```bash
./scanner resolve tunnel -i resolvers.txt -o result.json --domain t.example.com
```

### e2e dnstt

End-to-end connectivity test through a DNSTT SOCKS tunnel. Requires `dnstt-client` and `curl` in PATH.

```bash
./scanner e2e dnstt -i resolvers.txt -o result.json \
  --domain q.example.com --pubkey <hex-pubkey>
```

### e2e slipstream

End-to-end connectivity test through a Slipstream SOCKS tunnel. Requires `slipstream-client` and `curl` in PATH.

```bash
./scanner e2e slipstream -i resolvers.txt -o result.json \
  --domain s.example.com --cert /path/to/cert.pem
```

### chain

Run multiple scan steps in sequence, passing results in-memory. Only IPs that pass a step are forwarded to the next one.

```bash
./scanner chain -i resolvers.txt -o result.json \
  --step "ping" \
  --step "resolve:domain=google.com" \
  --step "resolve/tunnel:domain=q.example.com" \
  --step "e2e/dnstt:domain=q.example.com,pubkey=<hex-pubkey>" \
  --step "e2e/slipstream:domain=q.example.com,cert=/path/to/cert.pem"
```

Step format is `type:key=val,key=val`.

| Step               | Required params    | Optional params (defaults)                                              |
| ------------------ | ------------------ | ----------------------------------------------------------------------- |
| `ping`             | —                  | `count` (3), `timeout` (3)                                              |
| `resolve`          | `domain`           | `count` (3), `timeout` (3)                                              |
| `resolve/tunnel`   | `domain`           | `count` (3), `timeout` (3)                                              |
| `e2e/dnstt`        | `domain`, `pubkey` | `test-url` (https://httpbin.org/ip), `timeout` (5)                      |
| `e2e/slipstream`   | `domain`           | `cert`, `test-url` (https://httpbin.org/ip), `timeout` (5)              |

## Global Flags

| Flag               | Short | Description                              | Default  |
| ------------------ | ----- | ---------------------------------------- | -------- |
| `--input`          | `-i`  | Input file (text or JSON)                | required |
| `--output`         | `-o`  | Output JSON file                         | required |
| `--timeout`        | `-t`  | Timeout per attempt (seconds)            | 3        |
| `--count`          | `-c`  | Attempts per IP for ping/resolve checks  | 3        |
| `--workers`        |       | Concurrent workers                       | 50       |
| `--include-failed` |       | Also scan failed IPs from JSON input     | false    |
| `--ignore-rcode`   |       | DNS rcodes to ignore (see below)         | —        |

## Ignoring DNS Response Codes

Use `--ignore-rcode` to skip DNS responses with specific rcodes. This is useful when network middleboxes inject fake responses (e.g. NXDOMAIN) to censor domains — the scanner will discard those and wait for a legitimate reply.

Supported values: `nxdomain`, `servfail`, `refused`, `formerr`.

```bash
# Ignore injected NXDOMAIN responses
./scanner resolve -i resolvers.txt -o result.json --domain example.com --ignore-rcode nxdomain

# Ignore multiple rcodes
./scanner resolve -i resolvers.txt -o result.json --domain example.com --ignore-rcode nxdomain --ignore-rcode servfail

# Works with tunnel and chain commands too
./scanner resolve tunnel -i resolvers.txt -o result.json --domain t.example.com --ignore-rcode nxdomain
./scanner chain -i resolvers.txt -o result.json --ignore-rcode nxdomain \
  --step "resolve:domain=example.com" \
  --step "resolve/tunnel:domain=t.example.com"
```

Applies to `resolve`, `resolve tunnel`, and the corresponding `chain` steps. Does not apply to `ping` or `e2e` commands (which don't perform direct DNS queries).

## Metrics and Sorting

Each check captures timing metrics. Results are sorted ascending by the step's primary metric (lower = better).

| Step             | Metric       | Description                            |
| ---------------- | ------------ | -------------------------------------- |
| `ping`           | `ping_ms`    | Average RTT across successful pings    |
| `resolve`        | `resolve_ms` | Average resolve time across attempts   |
| `resolve/tunnel` | `resolve_ms` | Average NS + glue A query time across attempts |
| `e2e/dnstt`      | `e2e_ms`     | Time from start to successful curl     |
| `e2e/slipstream` | `e2e_ms`     | Time from start to successful curl     |

For ping/resolve checks, an IP is marked as failed if 3 consecutive attempts fail (early exit). Otherwise, the metric is the average of successful attempts.

## Input / Output

**Input** can be a plain text file (one IP per line) or a JSON file from a previous scan. When using JSON input, only `passed` IPs are scanned by default — use `--include-failed` to scan all.

**Output** is always JSON with structured records including per-IP metrics:

```json
{
  "passed": [
    {"ip": "1.1.1.1", "metrics": {"ping_ms": 4.2}},
    {"ip": "8.8.8.8", "metrics": {"ping_ms": 12.7}}
  ],
  "failed": [
    {"ip": "9.9.9.9"}
  ]
}
```

The `chain` command adds a `steps` array with per-step metadata, and passed records accumulate metrics from all steps:

```json
{
  "steps": [
    {
      "name": "ping",
      "tested": 10000,
      "passed": 9200,
      "failed": 800,
      "duration_secs": 15.1
    },
    {
      "name": "resolve",
      "tested": 9200,
      "passed": 8500,
      "failed": 700,
      "duration_secs": 42.3
    }
  ],
  "passed": [
    {"ip": "1.1.1.1", "metrics": {"ping_ms": 4.2, "resolve_ms": 15.3}}
  ],
  "failed": [
    {"ip": "9.9.9.9"}
  ]
}
```

## Related Projects

- [dnstc](https://github.com/net2share/dnstc) — DNS tunnel client
- [dnstm](https://github.com/net2share/dnstm) — DNS tunnel server
- [ir-resolvers](https://github.com/net2share/ir-resolvers) — Raw resolver IP list
