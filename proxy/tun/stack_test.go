//go:build windows

package tun

import (
	"bytes"
	"encoding/binary"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
)

// BenchmarkParseIPv4Header benchmarks IPv4 header parsing
func BenchmarkParseIPv4Header(b *testing.B) {
	// Create a valid IPv4 header
	packet := make([]byte, 20)
	packet[0] = 0x45 // Version 4, IHL 5
	binary.BigEndian.PutUint16(packet[2:4], 40)
	packet[8] = 64 // TTL
	packet[9] = ProtoTCP
	copy(packet[12:16], []byte{192, 168, 1, 1})
	copy(packet[16:20], []byte{192, 168, 1, 2})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		parseIPv4Header(packet)
	}
}

// BenchmarkParseIPv6Header benchmarks IPv6 header parsing
func BenchmarkParseIPv6Header(b *testing.B) {
	// Create a valid IPv6 header
	packet := make([]byte, 40)
	packet[0] = 0x60 // Version 6
	binary.BigEndian.PutUint16(packet[4:6], 20)
	packet[6] = ProtoTCP
	packet[7] = 64 // Hop limit

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		parseIPv6Header(packet)
	}
}

// BenchmarkParseTCPHeader benchmarks TCP header parsing
func BenchmarkParseTCPHeader(b *testing.B) {
	// Create a valid TCP header
	packet := make([]byte, 20)
	binary.BigEndian.PutUint16(packet[0:2], 12345) // src port
	binary.BigEndian.PutUint16(packet[2:4], 443)   // dst port
	binary.BigEndian.PutUint32(packet[4:8], 1000)  // seq
	binary.BigEndian.PutUint32(packet[8:12], 2000) // ack
	packet[12] = 0x50                              // data offset 5
	packet[13] = TCPFlagACK

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		parseTCPHeader(packet)
	}
}

// BenchmarkParseUDPHeader benchmarks UDP header parsing
func BenchmarkParseUDPHeader(b *testing.B) {
	// Create a valid UDP header
	packet := make([]byte, 8)
	binary.BigEndian.PutUint16(packet[0:2], 12345) // src port
	binary.BigEndian.PutUint16(packet[2:4], 53)    // dst port
	binary.BigEndian.PutUint16(packet[4:6], 100)   // length

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		parseUDPHeader(packet)
	}
}

// BenchmarkTCPConnectionRead benchmarks reading from TCP connection buffer
func BenchmarkTCPConnectionRead(b *testing.B) {
	conn := &TCPConnection{
		recvCond: sync.NewCond(&sync.Mutex{}),
	}
	conn.recvCond = sync.NewCond(&conn.mu)

	// Pre-fill buffer with test data
	testData := bytes.Repeat([]byte("test data for benchmarking "), 100)
	conn.recvBuffer.Write(testData)

	readBuf := make([]byte, 1400)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn.mu.Lock()
		if conn.recvBuffer.Len() == 0 {
			conn.recvBuffer.Write(testData)
		}
		conn.recvBuffer.Read(readBuf)
		conn.mu.Unlock()
	}
}

// BenchmarkTCPConnectionWrite simulates write path
func BenchmarkTCPConnectionWrite(b *testing.B) {
	testData := bytes.Repeat([]byte("x"), 1400)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Simulate packet building overhead
		packet := make([]byte, 20+20+len(testData)) // IP + TCP + data
		copy(packet[40:], testData)
	}
}

// BenchmarkChecksumIPv4 benchmarks IPv4 checksum calculation
func BenchmarkChecksumIPv4(b *testing.B) {
	header := make([]byte, 20)
	header[0] = 0x45
	binary.BigEndian.PutUint16(header[2:4], 60)
	header[8] = 64
	header[9] = ProtoTCP
	copy(header[12:16], []byte{192, 168, 1, 1})
	copy(header[16:20], []byte{192, 168, 1, 2})

	s := &stackSimple{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.setIPv4Checksum(header)
	}
}

// BenchmarkConnectionKeyLookup benchmarks sync.Map lookup
func BenchmarkConnectionKeyLookup(b *testing.B) {
	var conns sync.Map

	// Pre-populate with some connections
	for i := 0; i < 1000; i++ {
		key := ConnectionKey{
			SrcIP:   "192.168.1.1",
			DstIP:   "10.0.0.1",
			SrcPort: uint16(i + 1024),
			DstPort: 443,
			Proto:   ProtoTCP,
		}
		conns.Store(key, &TCPConnection{})
	}

	lookupKey := ConnectionKey{
		SrcIP:   "192.168.1.1",
		DstIP:   "10.0.0.1",
		SrcPort: 1500,
		DstPort: 443,
		Proto:   ProtoTCP,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conns.Load(lookupKey)
	}
}

// TestTCPConnectionBasic tests basic TCP connection operations
func TestTCPConnectionBasic(t *testing.T) {
	conn := &TCPConnection{
		SrcIP:      net.IPAddress([]byte{192, 168, 1, 1}),
		DstIP:      net.IPAddress([]byte{10, 0, 0, 1}),
		SrcPort:    12345,
		DstPort:    443,
		State:      TCPStateEstablished,
		LocalSeq:   1000,
		LocalAck:   2000,
		SendWindow: 65535,
		AckChan:    make(chan uint32, 64),
		LastActive: time.Now(),
		Created:    time.Now(),
	}
	conn.recvCond = sync.NewCond(&conn.mu)

	// Test buffer write/read
	testData := []byte("Hello, World!")
	conn.mu.Lock()
	conn.recvBuffer.Write(testData)
	conn.mu.Unlock()

	readBuf := make([]byte, 100)
	conn.mu.Lock()
	n, err := conn.recvBuffer.Read(readBuf)
	conn.mu.Unlock()

	if err != nil {
		t.Fatalf("Read error: %v", err)
	}
	if n != len(testData) {
		t.Fatalf("Expected %d bytes, got %d", len(testData), n)
	}
	if !bytes.Equal(readBuf[:n], testData) {
		t.Fatalf("Data mismatch: expected %q, got %q", testData, readBuf[:n])
	}
}

// TestIPv4HeaderParsing tests IPv4 header parsing
func TestIPv4HeaderParsing(t *testing.T) {
	packet := make([]byte, 20)
	packet[0] = 0x45 // Version 4, IHL 5
	binary.BigEndian.PutUint16(packet[2:4], 60)
	packet[8] = 64 // TTL
	packet[9] = ProtoTCP
	copy(packet[12:16], []byte{192, 168, 1, 100})
	copy(packet[16:20], []byte{10, 0, 0, 1})

	hdr := parseIPv4Header(packet)
	if hdr == nil {
		t.Fatal("Failed to parse IPv4 header")
	}

	if hdr.Version != 4 {
		t.Errorf("Expected version 4, got %d", hdr.Version)
	}
	if hdr.IHL != 5 {
		t.Errorf("Expected IHL 5, got %d", hdr.IHL)
	}
	if hdr.Protocol != ProtoTCP {
		t.Errorf("Expected protocol %d, got %d", ProtoTCP, hdr.Protocol)
	}
	if hdr.TTL != 64 {
		t.Errorf("Expected TTL 64, got %d", hdr.TTL)
	}
}

// TestTCPHeaderParsing tests TCP header parsing
func TestTCPHeaderParsing(t *testing.T) {
	packet := make([]byte, 20)
	binary.BigEndian.PutUint16(packet[0:2], 54321)
	binary.BigEndian.PutUint16(packet[2:4], 443)
	binary.BigEndian.PutUint32(packet[4:8], 123456789)
	binary.BigEndian.PutUint32(packet[8:12], 987654321)
	packet[12] = 0x50 // data offset 5
	packet[13] = TCPFlagSYN | TCPFlagACK
	binary.BigEndian.PutUint16(packet[14:16], 65535)

	hdr := parseTCPHeader(packet)
	if hdr == nil {
		t.Fatal("Failed to parse TCP header")
	}

	if hdr.SrcPort != 54321 {
		t.Errorf("Expected src port 54321, got %d", hdr.SrcPort)
	}
	if hdr.DstPort != 443 {
		t.Errorf("Expected dst port 443, got %d", hdr.DstPort)
	}
	if hdr.SeqNum != 123456789 {
		t.Errorf("Expected seq 123456789, got %d", hdr.SeqNum)
	}
	if hdr.AckNum != 987654321 {
		t.Errorf("Expected ack 987654321, got %d", hdr.AckNum)
	}
	if hdr.Flags != (TCPFlagSYN | TCPFlagACK) {
		t.Errorf("Expected flags SYN|ACK, got %d", hdr.Flags)
	}
}

// TestUDPHeaderParsing tests UDP header parsing
func TestUDPHeaderParsing(t *testing.T) {
	packet := make([]byte, 8)
	binary.BigEndian.PutUint16(packet[0:2], 12345)
	binary.BigEndian.PutUint16(packet[2:4], 53)
	binary.BigEndian.PutUint16(packet[4:6], 512)

	hdr := parseUDPHeader(packet)
	if hdr == nil {
		t.Fatal("Failed to parse UDP header")
	}

	if hdr.SrcPort != 12345 {
		t.Errorf("Expected src port 12345, got %d", hdr.SrcPort)
	}
	if hdr.DstPort != 53 {
		t.Errorf("Expected dst port 53, got %d", hdr.DstPort)
	}
	if hdr.Length != 512 {
		t.Errorf("Expected length 512, got %d", hdr.Length)
	}
}

// TestConnectionKeyEquality tests ConnectionKey comparison
func TestConnectionKeyEquality(t *testing.T) {
	key1 := ConnectionKey{
		SrcIP:   "192.168.1.1",
		DstIP:   "10.0.0.1",
		SrcPort: 12345,
		DstPort: 443,
		Proto:   ProtoTCP,
	}

	key2 := ConnectionKey{
		SrcIP:   "192.168.1.1",
		DstIP:   "10.0.0.1",
		SrcPort: 12345,
		DstPort: 443,
		Proto:   ProtoTCP,
	}

	key3 := ConnectionKey{
		SrcIP:   "192.168.1.2",
		DstIP:   "10.0.0.1",
		SrcPort: 12345,
		DstPort: 443,
		Proto:   ProtoTCP,
	}

	if key1 != key2 {
		t.Error("Identical keys should be equal")
	}

	if key1 == key3 {
		t.Error("Different keys should not be equal")
	}
}

// TestGenerateISN tests ISN generation
func TestGenerateISN(t *testing.T) {
	isn1 := generateISN()
	time.Sleep(time.Millisecond)
	isn2 := generateISN()

	// ISNs should be different (time-based)
	if isn1 == isn2 {
		t.Error("Sequential ISNs should be different")
	}
}

// BenchmarkGenerateISN benchmarks ISN generation
func BenchmarkGenerateISN(b *testing.B) {
	for i := 0; i < b.N; i++ {
		generateISN()
	}
}

// TestParseInvalidPackets tests handling of invalid packets
func TestParseInvalidPackets(t *testing.T) {
	// Too short IPv4
	if parseIPv4Header(make([]byte, 10)) != nil {
		t.Error("Should reject short IPv4 packet")
	}

	// Too short IPv6
	if parseIPv6Header(make([]byte, 30)) != nil {
		t.Error("Should reject short IPv6 packet")
	}

	// Too short TCP
	if parseTCPHeader(make([]byte, 10)) != nil {
		t.Error("Should reject short TCP packet")
	}

	// Too short UDP
	if parseUDPHeader(make([]byte, 4)) != nil {
		t.Error("Should reject short UDP packet")
	}

	// Empty packets
	if parseIPv4Header(nil) != nil {
		t.Error("Should reject nil IPv4 packet")
	}
	if parseTCPHeader(nil) != nil {
		t.Error("Should reject nil TCP packet")
	}
}
