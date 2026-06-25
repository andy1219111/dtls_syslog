package dtlssyslog

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/pion/dtls/v3"
)

// DTLSClient DTLS客户端
type DTLSClient struct {
	Conn net.Conn
	Addr string
	//心跳时间间隔
	HeartbeatInterval time.Duration
	//dtlsConfig        []dtls.ClientOption
	//写超时时间 单位秒
	WriteDeadline int
	ctx           context.Context
	cancel        context.CancelFunc
}

func NewDTLSClient(addr string, writeDeadline int) (*DTLSClient, error) {
	dtlsAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}

	configOptions := []dtls.ClientOption{
		dtls.WithInsecureSkipVerify(true),
		dtls.WithCipherSuites(
			dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			dtls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		),
		dtls.WithExtendedMasterSecret(dtls.RequireExtendedMasterSecret),
		dtls.WithFlightInterval(100 * time.Millisecond),
	}

	conn, err := dtls.DialWithOptions("udp", dtlsAddr, configOptions...)
	if err != nil {
		return nil, err
	}

	ctx, cancle := context.WithCancel(context.Background())
	dtlsClient := &DTLSClient{
		Addr: addr,
		Conn: conn,
		//dtlsConfig:        configOptions,
		HeartbeatInterval: 10,
		WriteDeadline:     writeDeadline,
		ctx:               ctx,
		cancel:            cancle,
	}
	err = dtlsClient.startHeartbeat()
	if err != nil {
		conn.Close()
		return nil, err
	}
	return dtlsClient, nil
}

func (c *DTLSClient) Write(msg []byte) error {
	if c.Conn == nil {
		return errors.New("conn is nil")
	}
	err := c.Conn.SetWriteDeadline(time.Now().Add(time.Duration(c.WriteDeadline) * time.Second))
	if err != nil {
		return err
	}
	_, err = c.Conn.Write(msg)
	return err
}

func (c *DTLSClient) startHeartbeat() error {
	if c.Conn == nil {
		return errors.New("conn is nil")
	}
	go func() {
		ticker := time.NewTicker(time.Duration(c.HeartbeatInterval) * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				err := c.Write([]byte("__heartbeat__"))
				if err != nil {
					return
				}
			case <-c.ctx.Done():
				return
			}
		}
	}()
	return nil
}

func (c *DTLSClient) Close() error {
	c.cancel()
	return c.Conn.Close()
}
