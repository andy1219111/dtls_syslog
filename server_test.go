package dtlssyslog

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pion/dtls/v3"
	"go.uber.org/zap/zaptest"
)

func TestNewDTLSSyslogServer(t *testing.T) {
	logger := zaptest.NewLogger(t)
	server := NewDTLSSyslogServer("127.0.0.1:0", "", "", logger.Sugar())

	if server == nil {
		t.Fatal("NewDTLSSyslogServer returned nil")
	}
	if server.Address != "127.0.0.1:0" {
		t.Errorf("expected address 127.0.0.1:0, got %s", server.Address)
	}
	if server.Listener != nil {
		t.Error("expected Listener to be nil before Start()")
	}
	if server.clients == nil {
		t.Error("expected clients map to be initialized")
	}
}

func TestDTLSSyslogServer_Start_AlreadyStarted(t *testing.T) {
	logger := zaptest.NewLogger(t)
	certFile := "../../certs/server.crt"
	keyFile := "../../certs/server.key"

	server := NewDTLSSyslogServer("127.0.0.1:0", certFile, keyFile, logger.Sugar())
	_, err := server.Start()
	if err != nil {
		t.Fatalf("first Start() failed: %v", err)
	}
	defer server.Stop()

	_, err = server.Start()
	if err == nil {
		t.Error("expected error when starting already started server, got nil")
	}
	if err.Error() != "server already started" {
		t.Errorf("expected 'server already started', got %q", err.Error())
	}
}

func TestDTLSSyslogServer_Start_BadCert(t *testing.T) {
	logger := zaptest.NewLogger(t)
	server := NewDTLSSyslogServer("127.0.0.1:0", "nonexistent.crt", "nonexistent.key", logger.Sugar())
	_, err := server.Start()
	if err == nil {
		t.Fatal("expected error with bad cert file, got nil")
	}
}

func TestDTLSSyslogServer_Stop(t *testing.T) {
	logger := zaptest.NewLogger(t)
	certFile := "../../certs/server.crt"
	keyFile := "../../certs/server.key"

	server := NewDTLSSyslogServer("127.0.0.1:0", certFile, keyFile, logger.Sugar())
	msgChan, err := server.Start()
	if err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	addr := server.Listener.Addr()
	t.Logf("server listening on %s", addr.String())

	time.Sleep(100 * time.Millisecond)

	server.Stop()

	select {
	case _, ok := <-msgChan:
		if ok {
			t.Error("expected msgChan to be closed after Stop(), got message")
		}
	default:
		t.Error("expected msgChan to be closed after Stop()")
	}
}

func TestDTLSSyslogServer_ReceiveMessage(t *testing.T) {
	logger := zaptest.NewLogger(t)
	certFile := "../../certs/server.crt"
	keyFile := "../../certs/server.key"

	server := NewDTLSSyslogServer("127.0.0.1:0", certFile, keyFile, logger.Sugar())
	msgChan, err := server.Start()
	if err != nil {
		t.Fatalf("Start() failed: %v", err)
	}
	defer server.Stop()

	addr := server.Listener.Addr().(*net.UDPAddr)
	t.Logf("connecting to %s", addr.String())

	config := &dtls.Config{
		InsecureSkipVerify: true,
		CipherSuites: []dtls.CipherSuiteID{
			dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			dtls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		},
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
		FlightInterval:       100 * time.Millisecond,
	}

	conn, err := dtls.Dial("udp", addr, config)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()

	testMsg := "test syslog message"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = conn.Write([]byte(testMsg))
	if err != nil {
		t.Fatalf("write failed: %v", err)
	}

	var received string
done:
	for {
		select {
		case msg, ok := <-msgChan:
			if !ok {
				break done
			}
			t.Logf("received: %s", msg)
			received = msg
			break done
		case <-ctx.Done():
			t.Fatal("timeout waiting for message")
		}
	}

	if received != testMsg {
		t.Errorf("expected %q, got %q", testMsg, received)
	}
}

func TestDTLSSyslogServer_MultipleMessages(t *testing.T) {
	logger := zaptest.NewLogger(t)
	certFile := "../../certs/server.crt"
	keyFile := "../../certs/server.key"

	server := NewDTLSSyslogServer("127.0.0.1:0", certFile, keyFile, logger.Sugar())
	msgChan, err := server.Start()
	if err != nil {
		t.Fatalf("Start() failed: %v", err)
	}
	defer server.Stop()

	addr := server.Listener.Addr().(*net.UDPAddr)

	config := &dtls.Config{
		InsecureSkipVerify: true,
		CipherSuites: []dtls.CipherSuiteID{
			dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			dtls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		},
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
		FlightInterval:       100 * time.Millisecond,
	}

	conn, err := dtls.Dial("udp", addr, config)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	messages := []string{
		"message 1",
		"message 2",
		"message 3",
	}

	received := make([]string, 0, len(messages))
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		for {
			select {
			case msg, ok := <-msgChan:
				if !ok {
					return
				}
				received = append(received, msg)
			case <-ctx.Done():
				return
			}
		}
	}()

	for _, msg := range messages {
		_, err = conn.Write([]byte(msg))
		if err != nil {
			t.Fatalf("write %q failed: %v", msg, err)
		}
		time.Sleep(50 * time.Millisecond)
	}

	wg.Wait()

	t.Logf("received %d messages", len(received))
	if len(received) < len(messages) {
		t.Errorf("expected %d messages, got %d: %v", len(messages), len(received), received)
	}
}

func TestDTLSSyslogServer_ConcurrentClients(t *testing.T) {
	logger := zaptest.NewLogger(t)
	certFile := "../../certs/server.crt"
	keyFile := "../../certs/server.key"

	server := NewDTLSSyslogServer("127.0.0.1:0", certFile, keyFile, logger.Sugar())
	msgChan, err := server.Start()
	if err != nil {
		t.Fatalf("Start() failed: %v", err)
	}
	defer server.Stop()

	addr := server.Listener.Addr().(*net.UDPAddr)

	numClients := 3
	messagesPerClient := 2
	totalExpected := numClients * messagesPerClient

	config := &dtls.Config{
		InsecureSkipVerify: true,
		CipherSuites: []dtls.CipherSuiteID{
			dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			dtls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		},
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
		FlightInterval:       100 * time.Millisecond,
	}

	var clientsWg sync.WaitGroup
	receivedChan := make(chan string, totalExpected)

	for i := 0; i < numClients; i++ {
		clientsWg.Add(1)
		go func(clientID int) {
			defer clientsWg.Done()

			conn, err := dtls.Dial("udp", addr, config)
			if err != nil {
				t.Errorf("client %d: dial failed: %v", clientID, err)
				return
			}
			defer conn.Close()

			for j := 0; j < messagesPerClient; j++ {
				msg := "test-syslog-client-" + fmt.Sprintf("test-syslog-client-%d-msg-%d", clientID, j)
				_, err = conn.Write([]byte(msg))
				if err != nil {
					t.Errorf("client %d: write failed: %v", clientID, err)
					return
				}
				time.Sleep(20 * time.Millisecond)
			}
		}(i)
	}

	go func() {
		for msg := range msgChan {
			receivedChan <- msg
		}
		close(receivedChan)
	}()

	clientsWg.Wait()
	server.Stop()

	received := make([]string, 0, totalExpected)
	for msg := range receivedChan {
		received = append(received, msg)
	}

	t.Logf("received %d/%d messages", len(received), totalExpected)
	if len(received) != totalExpected {
		t.Errorf("expected %d messages, got %d", totalExpected, len(received))
	}
}

func TestDTLSSyslogServer_Heartbeat(t *testing.T) {
	logger := zaptest.NewLogger(t)
	certFile := "../../certs/server.crt"
	keyFile := "../../certs/server.key"

	server := NewDTLSSyslogServer("127.0.0.1:0", certFile, keyFile, logger.Sugar())
	msgChan, err := server.Start()
	if err != nil {
		t.Fatalf("Start() failed: %v", err)
	}
	defer server.Stop()

	addr := server.Listener.Addr().(*net.UDPAddr)

	config := &dtls.Config{
		InsecureSkipVerify: true,
		CipherSuites: []dtls.CipherSuiteID{
			dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			dtls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		},
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
		FlightInterval:       100 * time.Millisecond,
	}

	conn, err := dtls.Dial("udp", addr, config)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()

	// Send heartbeat
	_, err = conn.Write([]byte("__heartbeat__"))
	if err != nil {
		t.Fatalf("write heartbeat failed: %v", err)
	}

	// Send real message
	testMsg := "real message after heartbeat"
	_, err = conn.Write([]byte(testMsg))
	if err != nil {
		t.Fatalf("write message failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var receivedHeartbeat bool
	var receivedOther string
	for {
		select {
		case msg, ok := <-msgChan:
			if !ok {
				return
			}
			if msg == "__heartbeat__" {
				receivedHeartbeat = true
			} else {
				receivedOther = msg
			}
			if receivedHeartbeat && receivedOther == testMsg {
				return
			}
		case <-ctx.Done():
			t.Fatalf("timeout waiting for messages: got heartbeat=%v, other=%q", receivedHeartbeat, receivedOther)
		}
	}
}
