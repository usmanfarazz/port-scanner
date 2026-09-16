# 🔍 Port Scanner

A fast, multi-threaded TCP port scanner written in pure Python, with lightweight
service detection and banner grabbing. Built as a learning project for network
security and reconnaissance.

> ⚠️ **For authorised testing only.** Only scan systems you own or have explicit
> written permission to test. Unauthorised scanning may be illegal.

## Features

- ⚡ Multi-threaded scanning for speed (configurable thread count)
- 🔎 Service detection for 25+ common ports (SSH, HTTP, MySQL, RDP, …)
- 🏷️ Banner grabbing to fingerprint running services
- 🎯 Flexible port ranges — single ports, lists, or ranges
- 🐍 No dependencies — uses only the Python standard library

## Requirements

- Python 3.7+

## Usage

```bash
# Scan the top 1024 ports (default)
python3 port_scanner.py scanme.nmap.org

# Scan specific ports
python3 port_scanner.py 192.168.1.1 -p 22,80,443

# Scan a range with more threads
python3 port_scanner.py 10.0.0.5 -p 1-5000 -t 200
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `host` | Target hostname or IP | required |
| `-p, --ports` | Ports to scan (`22,80` or `1-1024`) | `1-1024` |
| `-t, --threads` | Number of worker threads | `100` |
| `--timeout` | Connection timeout (seconds) | `0.5` |

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
- [ ] Export results to JSON / CSV
- [ ] Basic OS fingerprinting

## License

MIT © [Usman Faraz](https://github.com/usmanfarazz)
