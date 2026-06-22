# SNI-Spoof

Bypass DPI (Deep Packet Inspection) by injecting fake TLS ClientHello packets with spoofed SNI during the TCP handshake.

## How It Works

```
┌────────┐          ┌───────────┐          ┌────────────┐          ┌────────┐
│ Client │ ──TCP──▶ │ SNI-Spoof │ ──TCP──▶ │ DPI System │ ──TCP──▶ │ Server │
│        │          │  (proxy)  │          │            │          │        │
└────────┘          └─────┬─────┘          └──────┬─────┘          └────────┘
                          │                       │
                          │  1. SYN ─────────────▶│
                          │  2. SYN-ACK ◀─────────│
                          │  3. ACK ──────────────▶│
                          │  4. FAKE ClientHello ─▶│ ← DPI sees fake SNI
                          │     (wrong seq num)    │   (e.g. auth.vercel.com)
                          │                       │
                          │  5. Real traffic ─────▶│ ← DPI already made decision
                          │                       │   Server ignores fake packet
                          │                       │   (wrong seq was out of window)
```

1. Listens for incoming TCP connections on a local port
2. Establishes a TCP connection to the target server
3. During the TCP handshake, intercepts the ACK packet and injects a fake TLS ClientHello with a decoy SNI
4. The fake packet uses a wrong TCP sequence number so the real server ignores it, but DPI systems see the fake SNI and allow the connection
5. After injection, relays data transparently between client and server

## Bypass Method

### `wrong_seq`

After the TCP three-way handshake completes, a fake TLS ClientHello packet is injected with:
- A **wrong TCP sequence number** (shifted back by the payload length)
- The **fake SNI** hostname (e.g. `auth.vercel.com`)
- **PSH+ACK** flags set

The DPI system processes packets in order and sees the fake ClientHello first, associating the connection with the allowed SNI. The real server discards the fake packet because the sequence number is outside the expected receive window. Real application data then flows normally.

## Supported Platforms

| Platform | Packet Interception | Privileges Required |
|----------|-------------------|-------------------|
| Windows  | WinDivert         | Administrator     |
| Linux    | nfqueue + raw sockets | root          |

## Building

### Using GitHub Actions (Recommended)

1. Fork or push this repository to GitHub
2. Go to **Actions** tab
3. Click **Run workflow**
4. Download compiled artifacts from the workflow run

Artifacts produced:
- `sni-spoof-x86_64-pc-windows-msvc` — Windows 64-bit
- `sni-spoof-i686-pc-windows-msvc` — Windows 32-bit
- `sni-spoof-x86_64-unknown-linux-gnu` — Linux 64-bit (dynamic)
- `sni-spoof-x86_64-unknown-linux-musl` — Linux 64-bit (static)

### Local Build

```bash
# Install Rust: https://rustup.rs
cargo build --release
```

#### Linux Build Dependencies

```bash
sudo apt-get install libnetfilter-queue-dev libnfnetlink-dev
```

#### Windows Build Dependencies

Download [WinDivert 2.2.2](https://github.com/basil00/WinDivert/releases) and set the `WINDIVERT_PATH` environment variable to the directory containing the library files.

## Configuration

Edit `config.json` in the same directory as the executable:

```json
{
  "listen_host": "0.0.0.0",
  "listen_port": 40443,
  "connect_ip": "188.114.98.0",
  "connect_port": 443,
  "fake_sni": "auth.vercel.com",
  "bypass_method": "wrong_seq",
  "worker_threads": 4,
  "connection_timeout_secs": 10,
  "log_level": "info"
}
```

| Field | Description | Default |
|-------|-------------|---------|
| `listen_host` | Local address to listen on | — |
| `listen_port` | Local port to listen on | — |
| `connect_ip` | Target server IP address | — |
| `connect_port` | Target server port | — |
| `fake_sni` | Decoy SNI hostname for the fake ClientHello | — |
| `bypass_method` | Injection method (`wrong_seq`) | — |
| `worker_threads` | Number of async worker threads | `4` |
| `connection_timeout_secs` | Timeout for handshake and injection (seconds) | `10` |
| `log_level` | Log verbosity: `trace`, `debug`, `info`, `warn`, `error` | `"info"` |

## Usage

### Windows

1. Extract the downloaded zip to a folder
2. Make sure `WinDivert.dll` and `WinDivert64.sys` are in the same folder as `sni-spoof.exe`
3. Edit `config.json` with your settings
4. Right-click `sni-spoof.exe` → **Run as Administrator**

```
> sni-spoof.exe
2025-01-15T10:32:01Z INFO  SNI-Spoof v0.1.0
2025-01-15T10:32:01Z INFO  Listening on 0.0.0.0:40443
2025-01-15T10:32:01Z INFO  Target: 188.114.98.0:443
2025-01-15T10:32:01Z INFO  Fake SNI: auth.vercel.com
2025-01-15T10:32:01Z INFO  Bypass method: WrongSeq
2025-01-15T10:32:01Z INFO  Interface: 192.168.1.105
```

### Linux

```bash
# Make executable
chmod +x sni-spoof

# Edit config
nano config.json

# Run as root
sudo ./sni-spoof
```

### Connecting Through the Proxy

Configure your application to connect through the local proxy:

```
Host: 127.0.0.1
Port: 40443
```

The proxy transparently relays TCP traffic after performing the DPI bypass.

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `Failed to open WinDivert` | Run as Administrator on Windows |
| `Failed to open nfqueue` | Run as root on Linux (`sudo`) |
| `Failed to bind on port` | Another instance is running, or port is in use |
| `Connection to target timed out` | Check `connect_ip` is reachable |
| `Injection failed or timed out` | Increase `connection_timeout_secs`, check firewall |
| `Cannot read config file` | Ensure `config.json` is next to the executable |

## Log Levels

- **`error`** — Only critical failures
- **`warn`** — Unexpected packets and recoverable issues
- **`info`** — Startup info, connection summaries (recommended)
- **`debug`** — Per-connection lifecycle details
- **`trace`** — Maximum verbosity

## Project Structure

```
sni-spoof/
├── .github/workflows/build.yml   # CI/CD pipeline
├── src/
│   ├── main.rs                   # Entry point, signal handling
│   ├── config.rs                 # Configuration loading and validation
│   ├── connection.rs             # Connection state machine
│   ├── injector.rs               # Packet interception (Windows + Linux)
│   ├── net.rs                    # Network interface detection
│   ├── proxy.rs                  # TCP proxy and relay logic
│   └── tls.rs                    # Fake TLS ClientHello builder
├── Cargo.toml
├── config.json
└── README.md
```