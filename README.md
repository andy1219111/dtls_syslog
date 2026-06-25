# dtls-syslog

A DTLS-based syslog library for Go, providing both server and client implementations using [pion/dtls/v3](https://github.com/pion/dtls).

## Features

- **Server**: DTLS listener with multi-client support, heartbeat detection, graceful shutdown
- **Client**: DTLS dialer with automatic heartbeat, configurable write deadline
- Certificate loading via file path or in-memory bytes
- Concurrent client handling with per-client goroutines
- Idle timeout (30s) for client connections
- Built-in logging via `zap.SugaredLogger`

## Installation

```bash
go get github.com/andy1219111/dtls_syslog
```

## Quick Start

### Server

```go
package main

import (
    "log"
    dtlssyslog "github.com/andy1219111/dtls_syslog"
)

func main() {
    server := dtlssyslog.NewDTLSSyslogServer(":6514", "server.crt", "server.key", nil)
    msgChan, err := server.Start()
    if err != nil {
        log.Fatal(err)
    }

    go func() {
        for msg := range msgChan {
            log.Printf("Received: %s", msg)
        }
    }()

    // Wait for signal...
    // server.Stop()
}
```

Or load certificates from bytes:

```go
server := dtlssyslog.NewDTLSSyslogServerByCertBytes(":6514", certBytes, keyBytes, nil)
```

### Client

```go
package main

import (
    "log"
    dtlssyslog "github.com/andy1219111/dtls_syslog"
)

func main() {
    client, err := dtlssyslog.NewDTLSClient("127.0.0.1:6514", 5)
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    err = client.Write([]byte("hello syslog"))
    if err != nil {
        log.Fatal(err)
    }
}
```

## API

### Server

| Function / Method | Description |
|---|---|
| `NewDTLSSyslogServer(address, certFile, keyFile, logger)` | Create server with cert file paths |
| `NewDTLSSyslogServerByCertBytes(address, certBytes, keyBytes, logger)` | Create server with cert byte blocks |
| `Start() (<-chan string, error)` | Start listening, returns a channel of received messages |
| `Stop()` | Graceful shutdown: close listener, all client connections, and message channel |
| `Clients` | Map of `map[string]*ClientInfo` tracking connected clients |

**ClientInfo**:
- `Conn` - the DTLS connection
- `RemoteAddr` - remote address string
- `ConnectedAt` / `LastSeen` - timestamps

### Client

| Function / Method | Description |
|---|---|
| `NewDTLSClient(addr string, writeDeadline int) (*DTLSClient, error)` | Dial DTLS and start heartbeat. `writeDeadline` in seconds. |
| `Write(msg []byte) error` | Send a message with write deadline |
| `Close() error` | Close the connection |
| `HeartbeatInterval` | Heartbeat interval in seconds (default: 10) |

### Cipher Suites

Default cipher suites used:
- `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`
- `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`
- `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`

### Heartbeat

The client sends `__heartbeat__` messages periodically (every 10s by default). The server receives but does not forward heartbeat messages to the application channel.

## License

MIT
