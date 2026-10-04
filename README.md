# 🔍 Port Scanner

A fast, multi-threaded TCP port scanner written in pure Python, with lightweight
service detection and banner grabbing. Built as a learning project for network
security and reconnaissance.

> ⚠️ **For authorised testing only.** Only scan systems you own or have explicit
> written permission to test. Unauthorised scanning may be illegal.

## Features

- ⚡ Multi-threaded scanning for speed (configurable thread count)
- 🔎 Service detection for 30+ common ports (SSH, HTTP, MySQL, RDP, LDAP, WinRM, …)
- 🏷️ Banner grabbing to fingerprint running services
- 🎯 Flexible port ranges — single ports, lists, or ranges
- 💾 Save results to JSON or CSV for reports
- 🐍 No dependencies — uses only the Python standard library

## Requirements

- Python 3.7+

## Usage

```bash
# Scan the top 1024 ports (default)
python3 port_scanner.py scanme.nmap.org

# Quick first look: only well-known service ports
python3 port_scanner.py 192.168.1.1 --common

# Scan specific ports
python3 port_scanner.py 192.168.1.1 -p 22,80,443

# Scan a range with more threads
python3 port_scanner.py 10.0.0.5 -p 1-5000 -t 200

# Save the results for a report
python3 port_scanner.py 192.168.1.1 -o report.json
python3 port_scanner.py 192.168.1.1 -o report.csv
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `host` | Target hostname or IP | required |
| `-p, --ports` | Ports to scan (`22,80` or `1-1024`) | `1-1024` |
| `--common` | Scan only the well-known service ports (fast first look) | off |
| `-t, --threads` | Number of worker threads | `100` |
| `--timeout` | Connection timeout (seconds) | `0.5` |
| `-o, --output` | Save results to `.json` or `.csv` | — |

Port lists can mix single ports and ranges, e.g. `-p 22,80,8000-8100`.
A reversed range like `90-80` is read as `80-90`. Invalid input (`-p abc`,
`-t 0`, `--timeout 0`) is rejected with a clear message before scanning starts.

## Running the tests

```bash
python3 -m unittest discover -s tests -v
```

The tests start a tiny local server, so they need no network access.

## Example output

```
[*] Scanning scanme.nmap.org (45.33.32.156)
[*] 1024 ports | 100 threads | started 21:04:12

PORT    SERVICE       BANNER
--------------------------------------------------
22      SSH           SSH-2.0-OpenSSH_6.6.1p1 Ubuntu
80      HTTP

[+] Done. 2 open port(s) found.
```

## Roadmap

- [ ] UDP scanning
- [x] Export results to JSON / CSV
- [ ] Basic OS fingerprinting

## License

MIT © [Usman Faraz](https://github.com/usmanfarazz)
