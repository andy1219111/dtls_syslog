package dtlssyslog

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/pion/dtls/v3"
	"go.uber.org/zap"
)

// DTLSSyslogServer is the server of dtls syslog
type DTLSSyslogServer struct {
	Address        string
	Config         []dtls.ServerOption
	Listener       net.Listener
	certFile       string
	keyFile        string
	certBytesBlock []byte
	keyBytesBlock  []byte
	clients        map[string]*ClientInfo
	logger         *zap.SugaredLogger
	wg             sync.WaitGroup
	ctx            context.Context
	cancel         context.CancelFunc
	mu             sync.Mutex
	msgChan        chan string
}

// NewDTLSSyslogServer creates a new DTLSSyslogServer
func NewDTLSSyslogServer(address, certFile, keyFile string, logger *zap.SugaredLogger) *DTLSSyslogServer {
	ctx, cancelFunc := context.WithCancel(context.Background())
	return &DTLSSyslogServer{
		Address:  address,
		certFile: certFile,
		keyFile:  keyFile,
		clients:  make(map[string]*ClientInfo),
		logger:   logger,
		wg:       sync.WaitGroup{},
		ctx:      ctx,
		cancel:   cancelFunc,
		msgChan:  make(chan string),
	}
}

func NewDTLSSyslogServerByCertBytes(address string, certBytes []byte, keyBytes []byte, logger *zap.SugaredLogger) *DTLSSyslogServer {
	ctx, cancelFunc := context.WithCancel(context.Background())
	return &DTLSSyslogServer{
		Address:        address,
		certBytesBlock: certBytes,
		keyBytesBlock:  keyBytes,
		clients:        make(map[string]*ClientInfo),
		logger:         logger,
		wg:             sync.WaitGroup{},
		ctx:            ctx,
		cancel:         cancelFunc,
		msgChan:        make(chan string),
	}
}

func (s *DTLSSyslogServer) Start() (<-chan string, error) {
	if s.Listener != nil {
		return nil, errors.New("server already started")
	}

	var cert tls.Certificate
	var err error
	if s.certFile != "" && s.keyFile != "" {
		cert, err = tls.LoadX509KeyPair(s.certFile, s.keyFile)
	} else if len(s.certBytesBlock) != 0 && len(s.keyBytesBlock) != 0 {
		cert, err = tls.X509KeyPair(s.certBytesBlock, s.keyBytesBlock)
	} else {
		return nil, errors.New("the PEM is required")
	}

	if err != nil {
		return nil, err
	}

	configOptions := []dtls.ServerOption{
		dtls.WithCertificates(cert),
		//不强制执行客户端证书认证
		dtls.WithClientAuth(dtls.NoClientCert),
		dtls.WithCipherSuites(
			dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			dtls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		),
	}
	s.Config = configOptions
	addr, err := net.ResolveUDPAddr("udp", s.Address)
	if err != nil {
		return nil, err
	}
	s.Listener, err = dtls.ListenWithOptions("udp", addr, s.Config...)
	if err != nil {
		return nil, err
	}

	s.log("debug", fmt.Sprintf("DTLS server is running on %s", addr.String()))

	s.wg.Add(1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				s.logger.Errorf("acceptConn panic: %v\n%s", r, debug.Stack())
			}
		}()
		s.acceptConn(s.msgChan)
	}()

	return s.msgChan, nil
}

func (d *DTLSSyslogServer) acceptConn(msgChan chan string) {
	defer d.wg.Done()
	for {
		conn, err := d.Listener.Accept()
		if err != nil {
			if d.ctx.Err() != nil {
				return
			}
			d.logger.Error("accept the connection failed:", err)
			continue
		}
		addr := conn.RemoteAddr().String()
		//记录客户端信息
		d.mu.Lock()
		d.clients[addr] = &ClientInfo{
			Conn:        conn,
			RemoteAddr:  addr,
			ConnectedAt: time.Now(),
			LastSeen:    time.Now(),
		}
		d.mu.Unlock()
		d.log("debug", "new client connected:", addr)
		d.wg.Add(1)
		go func() {
			defer func() {
				if r := recover(); r != nil {
					d.logger.Errorf("handleClient panic: %v\n%s", r, debug.Stack())
				}
			}()
			d.handleClient(conn, msgChan)
		}()

	}
}

// handleClient 处理消息
func (d *DTLSSyslogServer) handleClient(conn net.Conn, msgChan chan string) {
	defer func() {
		d.removeClient(conn)
		_ = conn.Close()
		d.wg.Done()
	}()
	buf := make([]byte, 4096)

	for {
		if err := conn.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
			d.log("error", "set read deadline failed:", err)
			return
		}
		n, err := conn.Read(buf)
		if err != nil {
			if d.ctx.Err() != nil {
				return
			}
			// 超时：对端长时间无数据，按需关闭或继续等心跳
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				d.log("warn", "client idle timeout:", conn.RemoteAddr())
				return
			}
			// 对端主动关闭：EOF 即正常结束
			if errors.Is(err, io.EOF) {
				d.log("debug", "client closed connection:", conn.RemoteAddr())
				return
			}
			// 其它错误
			d.log("error", "read from client failed:", err)
			return
		}

		d.log("debug", "Received %d bytes", n)

		msg := strings.TrimSpace(string(buf[:n]))
		d.log("debug", "Received message: %s", msg)
		//防止msgChan关闭后继续发送消息导致panic
		select {
		case <-d.ctx.Done():
			return
		case msgChan <- msg:
		}
		if msg == "__heartbeat__" {
			continue
		}
	}
}

// removeClient 从客户端表中删除指定连接
func (d *DTLSSyslogServer) removeClient(conn net.Conn) {
	if conn == nil {
		return
	}
	if addr := conn.RemoteAddr(); addr != nil {
		d.mu.Lock()
		defer d.mu.Unlock()
		delete(d.clients, addr.String())
	}
}

func (d *DTLSSyslogServer) Stop() {
	// 取消上下文，通知所有处理函数退出
	d.cancel()
	if d.Listener != nil {
		d.Listener.Close()
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	for _, client := range d.clients {
		client.Conn.Close()
	}
	d.clients = make(map[string]*ClientInfo)

	d.wg.Wait()
	// 关闭消息通道，通知所有处理函数退出
	close(d.msgChan)
	d.log("debug", "DTLS server stopped")
}

func (d *DTLSSyslogServer) log(level string, args ...any) {
	if d.logger != nil {
		switch level {
		case "debug":
			d.logger.Debug(args...)
		case "info":
			d.logger.Info(args...)
		case "warn":
			d.logger.Warn(args...)
		case "panic":
			d.logger.Panic(args...)
		case "error":
			d.logger.Error(args...)
		default:
			d.logger.Debugf("unknow error:%s", level, args)
		}
	}
	log.Println(level, args)
}
