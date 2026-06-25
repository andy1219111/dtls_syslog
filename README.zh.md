# dtls-syslog

基于 DTLS 的 syslog 库，提供 Go 语言的 Server 和 Client 实现，底层使用 [pion/dtls/v3](https://github.com/pion/dtls)。

## 特性

- **服务端**：DTLS 监听器，支持多客户端并发连接、心跳检测、优雅关闭
- **客户端**：DTLS 拨号器，自动发送心跳、可配置写入超时
- 支持从文件路径或内存字节加载证书
- 每个客户端独立 goroutine 处理，互不阻塞
- 客户端空闲超时断开（30 秒无数据）
- 内置 `zap.SugaredLogger` 日志支持

## 安装

```bash
go get github.com/andy1219111/dtls_syslog
```

## 快速开始

### 服务端

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
            log.Printf("收到消息: %s", msg)
        }
    }()

    // 等待信号...
    // server.Stop()
}
```

或从字节加载证书：

```go
server := dtlssyslog.NewDTLSSyslogServerByCertBytes(":6514", certBytes, keyBytes, nil)
```

### 客户端

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

### 服务端

| 函数 / 方法 | 说明 |
|---|---|
| `NewDTLSSyslogServer(address, certFile, keyFile, logger)` | 通过证书文件路径创建服务端 |
| `NewDTLSSyslogServerByCertBytes(address, certBytes, keyBytes, logger)` | 通过证书字节创建服务端 |
| `Start() (<-chan string, error)` | 启动监听，返回消息 channel |
| `Stop()` | 优雅关闭：关闭 listener、所有客户端连接和消息 channel |
| `Clients` | 当前连接的客户端映射 `map[string]*ClientInfo` |

**ClientInfo**:
- `Conn` - DTLS 连接
- `RemoteAddr` - 远程地址
- `ConnectedAt` / `LastSeen` - 连接时间和最后活跃时间

### 客户端

| 函数 / 方法 | 说明 |
|---|---|
| `NewDTLSClient(addr string, writeDeadline int) (*DTLSClient, error)` | 拨号 DTLS 并启动心跳，`writeDeadline` 单位秒 |
| `Write(msg []byte) error` | 发送消息，带写入超时 |
| `Close() error` | 关闭连接 |
| `HeartbeatInterval` | 心跳间隔秒数（默认 10） |

### 加密套件

默认使用的加密套件：
- `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`
- `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`
- `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`

### 心跳

客户端每隔 10 秒发送 `__heartbeat__` 消息。服务端收到心跳包后会忽略，不会转发到应用层的消息 channel。

## 许可证

MIT
