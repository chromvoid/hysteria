package integration_tests

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/apernet/hysteria/core/v2/client"
	"github.com/apernet/hysteria/core/v2/errors"
	"github.com/apernet/hysteria/core/v2/internal/integration_tests/mocks"
	"github.com/apernet/hysteria/core/v2/server"
)

func TestTCPContextCancellationPreservesOtherStreams(t *testing.T) {
	blackhole, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blackhole.Close()
	deadline, stop := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer stop()
	started := time.Now()
	_, _, err = client.NewClientContext(deadline, &client.Config{ServerAddr: blackhole.LocalAddr(), TLSConfig: client.TLSConfig{InsecureSkipVerify: true}})
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Less(t, time.Since(started), time.Second)
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	echo := &tcpEchoServer{Listener: listener}
	defer echo.Close()
	go echo.Serve()
	blocked, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	outbound := mocks.NewMockOutbound(t)
	outbound.EXPECT().TCP("waiting.test:443").RunAndReturn(func(string) (net.Conn, error) {
		close(blocked)
		<-release
		return nil, io.EOF
	}).Once()
	outbound.EXPECT().TCP(listener.Addr().String()).RunAndReturn(func(address string) (net.Conn, error) {
		return net.DialTimeout("tcp", address, time.Second)
	}).Once()
	auth := mocks.NewMockAuthenticator(t)
	auth.EXPECT().Authenticate(mock.Anything, mock.Anything, mock.Anything).Return(true, "test")
	s, err := server.NewServer(&server.Config{TLSConfig: serverTLSConfig(), Conn: packet, Outbound: outbound, Authenticator: auth})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()
	connecting, connected := context.WithTimeout(context.Background(), 2*time.Second)
	c, _, err := client.NewClientContext(connecting, &client.Config{ServerAddr: packet.LocalAddr(), TLSConfig: client.TLSConfig{InsecureSkipVerify: true}})
	connected()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	dialer := c.(interface {
		TCPContext(context.Context, string) (net.Conn, error)
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan error, 1)
	go func() {
		conn, err := dialer.TCPContext(ctx, "waiting.test:443")
		if conn != nil {
			_ = conn.Close()
		}
		finished <- err
	}()
	select {
	case <-blocked:
	case <-time.After(2 * time.Second):
		t.Fatal("The server did not receive the pending stream")
	}
	cancel()
	select {
	case err := <-finished:
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("Canceling a stream did not stop its connection attempt")
	}
	ctx, done := context.WithTimeout(context.Background(), 2*time.Second)
	defer done()
	conn, err := dialer.TCPContext(ctx, listener.Addr().String())
	if err != nil {
		t.Fatal("Canceling one stream closed the shared transport")
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	_, err = conn.Write([]byte("alive"))
	assert.NoError(t, err)
	buffer := make([]byte, 5)
	_, err = io.ReadFull(conn, buffer)
	assert.NoError(t, err)
	assert.Equal(t, "alive", string(buffer))
}

// TestClientServerTCPClose tests whether the client/server propagates the close of a connection correctly.
// Closing one side of the connection should close the other side as well.
func TestClientServerTCPClose(t *testing.T) {
	// Create server
	udpConn, udpAddr, err := serverConn()
	assert.NoError(t, err)
	serverOb := mocks.NewMockOutbound(t)
	auth := mocks.NewMockAuthenticator(t)
	auth.EXPECT().Authenticate(mock.Anything, mock.Anything, mock.Anything).Return(true, "nobody")
	s, err := server.NewServer(&server.Config{
		TLSConfig:     serverTLSConfig(),
		Conn:          udpConn,
		Outbound:      serverOb,
		Authenticator: auth,
	})
	assert.NoError(t, err)
	defer s.Close()
	go s.Serve()

	// Create client
	c, _, err := client.NewClient(&client.Config{
		ServerAddr: udpAddr,
		TLSConfig:  client.TLSConfig{InsecureSkipVerify: true},
	})
	assert.NoError(t, err)
	defer c.Close()

	addr := "hi-and-goodbye:2333"

	// Test close from client side:
	// Client creates a connection, writes something, then closes it.
	// Server outbound connection should write the same thing, then close.
	sobConn := mocks.NewMockConn(t)
	sobConnCh := make(chan struct{}) // For close signal only
	sobConnChCloseFunc := sync.OnceFunc(func() { close(sobConnCh) })
	sobConn.EXPECT().Read(mock.Anything).RunAndReturn(func(bs []byte) (int, error) {
		<-sobConnCh
		return 0, io.EOF
	})
	sobConn.EXPECT().Write([]byte("happy")).Return(5, nil)
	sobConn.EXPECT().Close().RunAndReturn(func() error {
		sobConnChCloseFunc()
		return nil
	})
	serverOb.EXPECT().TCP(addr).Return(sobConn, nil).Once()
	conn, err := c.TCP(addr)
	assert.NoError(t, err)
	_, err = conn.Write([]byte("happy"))
	assert.NoError(t, err)
	err = conn.Close()
	assert.NoError(t, err)
	time.Sleep(1 * time.Second)
	mock.AssertExpectationsForObjects(t, sobConn, serverOb)

	// Test close from server side:
	// Client creates a connection.
	// Server outbound connection reads something, then closes.
	// Client connection should read the same thing, then close.
	sobConn = mocks.NewMockConn(t)
	sobConnCh2 := make(chan []byte, 1)
	sobConn.EXPECT().Read(mock.Anything).RunAndReturn(func(bs []byte) (int, error) {
		d := <-sobConnCh2
		if d == nil {
			return 0, io.EOF
		} else {
			return copy(bs, d), nil
		}
	})
	sobConn.EXPECT().Close().Return(nil)
	serverOb.EXPECT().TCP(addr).Return(sobConn, nil).Once()
	conn, err = c.TCP(addr)
	assert.NoError(t, err)
	sobConnCh2 <- []byte("happy")
	close(sobConnCh2)
	bs, err := io.ReadAll(conn)
	assert.NoError(t, err)
	assert.Equal(t, "happy", string(bs))
}

// TestClientServerUDPIdleTimeout tests whether the server's UDP idle timeout works correctly.
func TestClientServerUDPIdleTimeout(t *testing.T) {
	// Create server
	udpConn, udpAddr, err := serverConn()
	assert.NoError(t, err)
	serverOb := mocks.NewMockOutbound(t)
	auth := mocks.NewMockAuthenticator(t)
	auth.EXPECT().Authenticate(mock.Anything, mock.Anything, mock.Anything).Return(true, "nobody")
	eventLogger := mocks.NewMockEventLogger(t)
	eventLogger.EXPECT().Connect(mock.Anything, "nobody", mock.Anything).Once()
	eventLogger.EXPECT().Disconnect(mock.Anything, "nobody", mock.Anything).Maybe() // Depends on the timing, don't care
	s, err := server.NewServer(&server.Config{
		TLSConfig:      serverTLSConfig(),
		Conn:           udpConn,
		Outbound:       serverOb,
		UDPIdleTimeout: 2 * time.Second,
		Authenticator:  auth,
		EventLogger:    eventLogger,
	})
	assert.NoError(t, err)
	defer s.Close()
	go s.Serve()

	// Create client
	c, _, err := client.NewClient(&client.Config{
		ServerAddr: udpAddr,
		TLSConfig:  client.TLSConfig{InsecureSkipVerify: true},
	})
	assert.NoError(t, err)
	defer c.Close()

	addr := "spy.x.family:2023"

	// On the client side, create a UDP session and send a packet every 1 second,
	// 4 packets in total. The server should have one UDP session and receive all
	// 4 packets. Then the UDP connection on the server side will receive a packet
	// every 1 second, 4 packets in total. The client session should receive all
	// 4 packets. Then the session will be idle for 3 seconds - should be enough
	// to trigger the server's UDP idle timeout.
	sobConn := mocks.NewMockUDPConn(t)
	sobConnCh := make(chan []byte, 1)
	sobConnChCloseFunc := sync.OnceFunc(func() { close(sobConnCh) })
	sobConn.EXPECT().ReadFrom(mock.Anything).RunAndReturn(func(bs []byte) (int, string, error) {
		d := <-sobConnCh
		if d == nil {
			return 0, "", io.EOF
		} else {
			return copy(bs, d), addr, nil
		}
	})
	sobConn.EXPECT().WriteTo([]byte("happy"), addr).Return(5, nil).Times(4)
	serverOb.EXPECT().UDP(addr).Return(sobConn, nil).Once()
	eventLogger.EXPECT().UDPRequest(mock.Anything, mock.Anything, uint32(1), addr).Once()
	cu, err := c.UDP()
	assert.NoError(t, err)
	// Client sends 4 packets
	for i := 0; i < 4; i++ {
		err = cu.Send([]byte("happy"), addr)
		assert.NoError(t, err)
		time.Sleep(1 * time.Second)
	}
	// Client receives 4 packets
	go func() {
		for i := 0; i < 4; i++ {
			sobConnCh <- []byte("sad")
			time.Sleep(1 * time.Second)
		}
	}()
	for i := 0; i < 4; i++ {
		bs, rAddr, err := cu.Receive()
		assert.NoError(t, err)
		assert.Equal(t, "sad", string(bs))
		assert.Equal(t, addr, rAddr)
	}
	// Now we wait for 3 seconds, the server should close the UDP session.
	sobConn.EXPECT().Close().RunAndReturn(func() error {
		sobConnChCloseFunc()
		return nil
	})
	eventLogger.EXPECT().UDPError(mock.Anything, mock.Anything, uint32(1), nil).Once()
	time.Sleep(3 * time.Second)
}

// TestClientServerClientShutdown tests whether the server can handle the client's shutdown correctly.
func TestClientServerClientShutdown(t *testing.T) {
	// Create server
	udpConn, udpAddr, err := serverConn()
	assert.NoError(t, err)
	auth := mocks.NewMockAuthenticator(t)
	auth.EXPECT().Authenticate(mock.Anything, mock.Anything, mock.Anything).Return(true, "nobody")
	eventLogger := mocks.NewMockEventLogger(t)
	eventLogger.EXPECT().Connect(mock.Anything, "nobody", mock.Anything).Once()
	s, err := server.NewServer(&server.Config{
		TLSConfig:     serverTLSConfig(),
		Conn:          udpConn,
		Authenticator: auth,
		EventLogger:   eventLogger,
	})
	assert.NoError(t, err)
	defer s.Close()
	go s.Serve()

	// Create client
	c, _, err := client.NewClient(&client.Config{
		ServerAddr: udpAddr,
		TLSConfig:  client.TLSConfig{InsecureSkipVerify: true},
	})
	assert.NoError(t, err)

	// Close the client - expect disconnect event on the server side.
	// Since client.Close() sends HTTP3 ErrCodeNoError, the error should be nil.
	eventLogger.EXPECT().Disconnect(mock.Anything, "nobody", nil).Once()
	_ = c.Close()
	time.Sleep(1 * time.Second)
}

// TestClientServerServerShutdown tests whether the client can handle the server's shutdown correctly.
func TestClientServerServerShutdown(t *testing.T) {
	// Create server
	udpConn, udpAddr, err := serverConn()
	assert.NoError(t, err)
	auth := mocks.NewMockAuthenticator(t)
	auth.EXPECT().Authenticate(mock.Anything, mock.Anything, mock.Anything).Return(true, "nobody")
	s, err := server.NewServer(&server.Config{
		TLSConfig:     serverTLSConfig(),
		Conn:          udpConn,
		Authenticator: auth,
	})
	assert.NoError(t, err)
	go s.Serve()

	// Create client
	c, _, err := client.NewClient(&client.Config{
		ServerAddr: udpAddr,
		TLSConfig:  client.TLSConfig{InsecureSkipVerify: true},
		QUICConfig: client.QUICConfig{
			MaxIdleTimeout: 4 * time.Second,
		},
	})
	assert.NoError(t, err)

	// Close the server - expect the client to return ClosedError for both TCP & UDP calls.
	_ = s.Close()

	_, err = c.TCP("whatever")
	_, ok := err.(errors.ClosedError)
	assert.True(t, ok)

	time.Sleep(1 * time.Second) // Allow some time for the error to be propagated to the UDP session manager

	_, err = c.UDP()
	_, ok = err.(errors.ClosedError)
	assert.True(t, ok)

	assert.NoError(t, c.Close())
}
