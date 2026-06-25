package dtlssyslog

import (
	"net"
	"time"
)

// ClientInfo 连接上来的客户端的信息
type ClientInfo struct {
	Conn        net.Conn
	RemoteAddr  string
	ConnectedAt time.Time
	LastSeen    time.Time
}
