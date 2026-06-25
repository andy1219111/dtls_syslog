// /home/work/code/dtls-syslog/lib/dtls_syslog/client_test.go
package dtlssyslog

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap/zaptest"
)

// startTestServer 启动测试用的 DTLS 服务器，返回地址和清理函数
func startTestServer(t *testing.T) (string, func()) {
	t.Helper()
	logger := zaptest.NewLogger(t)
	certFile := "../../certs/server.crt"
	keyFile := "../../certs/server.key"

	server := NewDTLSSyslogServer("127.0.0.1:0", certFile, keyFile, logger.Sugar())
	msgChan, err := server.Start()
	if err != nil {
		t.Fatalf("failed to start test server: %v", err)
	}

	go func() {
		for range msgChan {
		}
	}()

	time.Sleep(100 * time.Millisecond)

	addr := server.Listener.Addr().String()
	return addr, func() { server.Stop() }
}

func TestNewDTLSClient(t *testing.T) {
	addr, cleanup := startTestServer(t)
	defer cleanup()

	client, err := NewDTLSClient(addr, 5)
	if err != nil {
		t.Fatalf("NewDTLSClient failed: %v", err)
	}
	defer client.Close()

	if client == nil {
		t.Fatal("NewDTLSClient returned nil")
	}
	if client.Conn == nil {
		t.Error("client.Conn should not be nil")
	}
	if client.Addr != addr {
		t.Errorf("expected addr %q, got %q", addr, client.Addr)
	}
	if client.HeartbeatInterval != 10 {
		t.Errorf("expected HeartbeatInterval 10, got %d", client.HeartbeatInterval)
	}
}

func TestNewDTLSClient_BadAddress(t *testing.T) {
	_, err := NewDTLSClient("invalid:address:99999", 5)
	if err == nil {
		t.Fatal("expected error with bad address, got nil")
	}
}

func TestDTLSClient_Write(t *testing.T) {
	addr, cleanup := startTestServer(t)
	defer cleanup()

	client, err := NewDTLSClient(addr, 5)
	if err != nil {
		t.Fatalf("NewDTLSClient failed: %v", err)
	}
	defer client.Close()

	testMsg := "test syslog message from client"
	err = client.Write([]byte(testMsg))
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
}

func TestDTLSClient_WriteNilConn(t *testing.T) {
	client := &DTLSClient{
		Conn:          nil,
		WriteDeadline: 5,
	}

	err := client.Write([]byte("test"))
	if err == nil {
		t.Fatal("expected error when writing with nil conn, got nil")
	}
	if err.Error() != "conn is nil" {
		t.Errorf("expected 'conn is nil', got %q", err.Error())
	}
}

func TestDTLSClient_WriteDeadline(t *testing.T) {
	addr, cleanup := startTestServer(t)
	defer cleanup()

	client, err := NewDTLSClient(addr, 5)
	if err != nil {
		t.Fatalf("NewDTLSClient failed: %v", err)
	}
	defer client.Close()

	// WriteDeadline=5 秒，应该正常写入
	err = client.Write([]byte("deadline test"))
	if err != nil {
		t.Fatalf("Write with deadline failed: %v", err)
	}

	// 设置为 0 会导致立即超时（time.Now() 作为 deadline）
	client.WriteDeadline = 0
	err = client.Write([]byte("should fail"))
	if err == nil {
		t.Error("expected Write with zero deadline to fail")
	}
}

func TestDTLSClient_Close(t *testing.T) {
	addr, cleanup := startTestServer(t)
	defer cleanup()

	client, err := NewDTLSClient(addr, 5)
	if err != nil {
		t.Fatalf("NewDTLSClient failed: %v", err)
	}

	err = client.Close()
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// 关闭后 Write 应该失败
	err = client.Write([]byte("after close"))
	if err == nil {
		t.Error("expected Write after Close to fail")
	}
}

func TestDTLSClient_CloseTwice(t *testing.T) {
	addr, cleanup := startTestServer(t)
	defer cleanup()

	client, err := NewDTLSClient(addr, 5)
	if err != nil {
		t.Fatalf("NewDTLSClient failed: %v", err)
	}

	err = client.Close()
	if err != nil {
		t.Fatalf("first Close failed: %v", err)
	}

	// 第二次 Close 可能返回错误（连接已关闭），但不应该 panic
	err = client.Close()
	if err != nil {
		t.Logf("second Close returned error (expected): %v", err)
	}
}

func TestDTLSClient_Heartbeat(t *testing.T) {
	addr, cleanup := startTestServer(t)
	defer cleanup()

	client, err := NewDTLSClient(addr, 5)
	if err != nil {
		t.Fatalf("NewDTLSClient failed: %v", err)
	}
	defer client.Close()

	// 修改心跳间隔为 1 秒，加速测试
	client.HeartbeatInterval = 1

	// 等待至少一次心跳触发
	time.Sleep(1500 * time.Millisecond)

	// 心跳后连接仍然有效，能正常写入
	err = client.Write([]byte("after heartbeat"))
	if err != nil {
		t.Fatalf("Write after heartbeat failed: %v", err)
	}
}

func TestDTLSClient_MultipleWrites(t *testing.T) {
	addr, cleanup := startTestServer(t)
	defer cleanup()

	client, err := NewDTLSClient(addr, 5)
	if err != nil {
		t.Fatalf("NewDTLSClient failed: %v", err)
	}
	defer client.Close()

	messages := []string{
		"message 1",
		"message 2",
		"message 3",
		"message 4",
		"message 5",
	}

	for _, msg := range messages {
		err = client.Write([]byte(msg))
		if err != nil {
			t.Fatalf("Write %q failed: %v", msg, err)
		}
	}
}

func TestDTLSClient_ConcurrentWrite(t *testing.T) {
	addr, cleanup := startTestServer(t)
	defer cleanup()

	client, err := NewDTLSClient(addr, 5)
	if err != nil {
		t.Fatalf("NewDTLSClient failed: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		for i := 0; i < 10; i++ {
			msg := "test-syslog-concurrent"
			err := client.Write([]byte(msg))
			if err != nil {
				t.Errorf("concurrent Write failed: %v", err)
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		done <- struct{}{}
	}()

	select {
	case <-done:
		// OK
	case <-ctx.Done():
		t.Fatal("timeout waiting for concurrent writes")
	}
}
