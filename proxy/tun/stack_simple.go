//go:build windows

package tun

import (
	"bytes"
	"context"
	"encoding/binary"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"golang.org/x/sys/windows"
)

// Simple TCP/IP stack for TUN - no gVisor dependency
// Principles: speed, efficiency, simplicity

const (
	// IP protocol numbers
	ProtoICMP = 1
	ProtoTCP  = 6
	ProtoUDP  = 17

	// TCP flags
	TCPFlagFIN = 0x01
	TCPFlagSYN = 0x02
	TCPFlagRST = 0x04
	TCPFlagPSH = 0x08
	TCPFlagACK = 0x10
	TCPFlagURG = 0x20

	// TCP states (simplified)
	TCPStateClosed      = 0
	TCPStateListen      = 1
	TCPStateSynReceived = 2
	TCPStateEstablished = 3
	TCPStateFinWait1    = 4
	TCPStateFinWait2    = 5
	TCPStateClosing     = 6
	TCPStateCloseWait   = 7
	TCPStateLastAck     = 8
	TCPStateTimeWait    = 9

	// Timeouts
	TCPIdleTimeout = 5 * time.Minute
	UDPIdleTimeout = 2 * time.Minute
)

// IPv4Header represents parsed IPv4 header
type IPv4Header struct {
	Version    uint8
	IHL        uint8 // header length in 32-bit words
	TOS        uint8
	TotalLen   uint16
	ID         uint16
	Flags      uint8
	FragOffset uint16
	TTL        uint8
	Protocol   uint8
	Checksum   uint16
	SrcIP      [4]byte
	DstIP      [4]byte
}

// IPv6Header represents parsed IPv6 header
type IPv6Header struct {
	Version      uint8
	TrafficClass uint8
	FlowLabel    uint32
	PayloadLen   uint16
	NextHeader   uint8
	HopLimit     uint8
	SrcIP        [16]byte
	DstIP        [16]byte
}

// TCPHeader represents parsed TCP header
type TCPHeader struct {
	SrcPort    uint16
	DstPort    uint16
	SeqNum     uint32
	AckNum     uint32
	DataOffset uint8 // header length in 32-bit words
	Flags      uint8
	Window     uint16
	Checksum   uint16
	UrgentPtr  uint16
}

// UDPHeader represents parsed UDP header
type UDPHeader struct {
	SrcPort  uint16
	DstPort  uint16
	Length   uint16
	Checksum uint16
}

// outOfOrderPacket holds a packet that arrived out of order
type outOfOrderPacket struct {
	seq  uint32
	data []byte
}

// TCPConnection tracks a TCP connection state
type TCPConnection struct {
	mu sync.Mutex

	// Connection identifiers
	SrcIP   net.Address
	DstIP   net.Address
	SrcPort uint16
	DstPort uint16

	// TCP state
	State    int
	LocalSeq uint32
	LocalAck uint32
	RemSeq   uint32
	RemAck   uint32

	// Flow control
	SendWindow  uint32      // Remote window size
	SendUnacked uint32      // Bytes sent but not yet ACKed
	AckChan     chan uint32 // Channel to signal ACK received
	LastAckTime time.Time

	// Buffers - using bytes.Buffer for better throughput
	recvBuffer bytes.Buffer
	recvCond   *sync.Cond         // Condition variable to signal new data
	oooBuffer  []outOfOrderPacket // Out-of-order packets waiting to be processed

	// Timestamps
	LastActive time.Time
	Created    time.Time

	// Close handling
	closed   bool
	closeErr error
}

// ConnectionKey uniquely identifies a connection
type ConnectionKey struct {
	SrcIP   string
	DstIP   string
	SrcPort uint16
	DstPort uint16
	Proto   uint8
}

// stackSimple is a minimal TCP/IP stack implementation
type stackSimple struct {
	ctx         context.Context
	cancel      context.CancelFunc
	tun         *WindowsTun
	handler     *Handler
	idleTimeout time.Duration

	// Connection tracking
	tcpConns sync.Map // ConnectionKey -> *TCPConnection
	udpConns sync.Map // ConnectionKey -> *udpConn

	// Packet writing
	writeMu sync.Mutex
}

// NewSimpleStack creates a new simple stack instance
func NewSimpleStack(ctx context.Context, options StackOptions, handler *Handler) (Stack, error) {
	ctx, cancel := context.WithCancel(ctx)
	s := &stackSimple{
		ctx:         ctx,
		cancel:      cancel,
		tun:         options.Tun.(*WindowsTun),
		handler:     handler,
		idleTimeout: options.IdleTimeout,
	}
	return s, nil
}

// Start begins packet processing
func (s *stackSimple) Start() error {
	go s.readLoop()
	go s.cleanupLoop()
	return nil
}

// Close shuts down the stack
func (s *stackSimple) Close() error {
	s.cancel()

	// Close all TCP connections
	s.tcpConns.Range(func(key, value interface{}) bool {
		if conn, ok := value.(*TCPConnection); ok {
			conn.Close()
		}
		s.tcpConns.Delete(key)
		return true
	})

	// Close all UDP connections
	s.udpConns.Range(func(key, value interface{}) bool {
		if conn, ok := value.(*udpConn); ok {
			conn.Close()
		}
		s.udpConns.Delete(key)
		return true
	})

	return nil
}

// readLoop reads packets from TUN and dispatches them
func (s *stackSimple) readLoop() {
	readWait := s.tun.session.ReadWaitEvent()

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
			packet, err := s.tun.session.ReceivePacket()
			if err != nil {
				procyield(1)
				_, _ = windows.WaitForSingleObject(readWait, windows.INFINITE)
				continue
			}
			s.processPacket(packet)
		}
	}
}

// processPacket handles an incoming IP packet
func (s *stackSimple) processPacket(packet []byte) {
	defer s.tun.session.ReleaseReceivePacket(packet)

	if len(packet) < 1 {
		return
	}

	version := packet[0] >> 4
	switch version {
	case 4:
		s.processIPv4(packet)
	case 6:
		s.processIPv6(packet)
	}
}

// processIPv4 handles IPv4 packets
func (s *stackSimple) processIPv4(packet []byte) {
	if len(packet) < 20 {
		return
	}

	hdr := parseIPv4Header(packet)
	if hdr == nil {
		return
	}

	headerLen := int(hdr.IHL) * 4
	if len(packet) < headerLen {
		return
	}

	payload := packet[headerLen:]
	srcIP := net.IPAddress(hdr.SrcIP[:])
	dstIP := net.IPAddress(hdr.DstIP[:])

	switch hdr.Protocol {
	case ProtoTCP:
		s.processTCP(srcIP, dstIP, payload)
	case ProtoUDP:
		s.processUDP(srcIP, dstIP, payload)
	}
}

// processIPv6 handles IPv6 packets
func (s *stackSimple) processIPv6(packet []byte) {
	if len(packet) < 40 {
		return
	}

	hdr := parseIPv6Header(packet)
	if hdr == nil {
		return
	}

	payload := packet[40:]
	srcIP := net.IPAddress(hdr.SrcIP[:])
	dstIP := net.IPAddress(hdr.DstIP[:])

	switch hdr.NextHeader {
	case ProtoTCP:
		s.processTCP(srcIP, dstIP, payload)
	case ProtoUDP:
		s.processUDP(srcIP, dstIP, payload)
	}
}

// processTCP handles TCP segments
func (s *stackSimple) processTCP(srcIP, dstIP net.Address, payload []byte) {
	if len(payload) < 20 {
		return
	}

	tcpHdr := parseTCPHeader(payload)
	if tcpHdr == nil {
		return
	}

	dataOffset := int(tcpHdr.DataOffset) * 4
	if len(payload) < dataOffset {
		return
	}

	tcpData := payload[dataOffset:]

	key := ConnectionKey{
		SrcIP:   srcIP.String(),
		DstIP:   dstIP.String(),
		SrcPort: tcpHdr.SrcPort,
		DstPort: tcpHdr.DstPort,
		Proto:   ProtoTCP,
	}

	// Handle SYN - new connection
	if tcpHdr.Flags&TCPFlagSYN != 0 && tcpHdr.Flags&TCPFlagACK == 0 {
		s.handleTCPSyn(key, srcIP, dstIP, tcpHdr)
		return
	}

	// Find existing connection
	connVal, exists := s.tcpConns.Load(key)
	if !exists {
		s.sendTCPRst(srcIP, dstIP, tcpHdr)
		return
	}

	conn := connVal.(*TCPConnection)
	conn.mu.Lock()
	defer conn.mu.Unlock()

	conn.LastActive = time.Now()

	// Handle RST
	if tcpHdr.Flags&TCPFlagRST != 0 {
		conn.State = TCPStateClosed
		conn.closed = true
		conn.recvCond.Broadcast()
		s.tcpConns.Delete(key)
		return
	}

	// Handle FIN
	if tcpHdr.Flags&TCPFlagFIN != 0 {
		s.handleTCPFin(conn, tcpHdr)
		return
	}

	// Handle ACK with data
	if tcpHdr.Flags&TCPFlagACK != 0 {
		oldRemAck := conn.RemAck
		conn.RemAck = tcpHdr.AckNum
		conn.SendWindow = uint32(tcpHdr.Window)

		if tcpHdr.AckNum > oldRemAck {
			ackedBytes := tcpHdr.AckNum - oldRemAck
			if conn.SendUnacked >= ackedBytes {
				conn.SendUnacked -= ackedBytes
			} else {
				conn.SendUnacked = 0
			}
			conn.LastAckTime = time.Now()

			if conn.AckChan != nil {
				select {
				case conn.AckChan <- tcpHdr.AckNum:
				default:
				}
			}
		}

		// If there's data, write to buffer
		if len(tcpData) > 0 {
			// Validate sequence number - only accept expected data
			expectedSeq := conn.LocalAck
			if tcpHdr.SeqNum == expectedSeq {
				// In-order packet - accept it
				conn.recvBuffer.Write(tcpData)
				conn.LocalAck += uint32(len(tcpData))

				// Check if any out-of-order packets can now be processed
				s.processOOOBuffer(conn)

				// Signal waiting readers
				conn.recvCond.Signal()

				// Send ACK
				s.sendTCPAck(conn)
			} else if tcpHdr.SeqNum < expectedSeq {
				// Duplicate/old packet - just re-ACK
				s.sendTCPAck(conn)
			} else {
				// Future packet - store in out-of-order buffer
				if len(conn.oooBuffer) < 64 { // Limit buffer size
					dataCopy := make([]byte, len(tcpData))
					copy(dataCopy, tcpData)
					conn.oooBuffer = append(conn.oooBuffer, outOfOrderPacket{
						seq:  tcpHdr.SeqNum,
						data: dataCopy,
					})
				}
				// Send duplicate ACK to trigger fast retransmit
				s.sendTCPAck(conn)
			}
		}
	}
}

// processOOOBuffer checks if any out-of-order packets can now be processed
func (s *stackSimple) processOOOBuffer(conn *TCPConnection) {
	changed := true
	for changed {
		changed = false
		for i := 0; i < len(conn.oooBuffer); i++ {
			pkt := conn.oooBuffer[i]
			if pkt.seq == conn.LocalAck {
				// This packet is now in order
				conn.recvBuffer.Write(pkt.data)
				conn.LocalAck += uint32(len(pkt.data))
				// Remove from buffer
				conn.oooBuffer = append(conn.oooBuffer[:i], conn.oooBuffer[i+1:]...)
				changed = true
				break
			}
		}
	}
}

// handleTCPSyn processes a new TCP connection
func (s *stackSimple) handleTCPSyn(key ConnectionKey, srcIP, dstIP net.Address, tcpHdr *TCPHeader) {
	conn := &TCPConnection{
		SrcIP:       srcIP,
		DstIP:       dstIP,
		SrcPort:     tcpHdr.SrcPort,
		DstPort:     tcpHdr.DstPort,
		State:       TCPStateSynReceived,
		LocalSeq:    generateISN(),
		LocalAck:    tcpHdr.SeqNum + 1,
		RemSeq:      tcpHdr.SeqNum,
		SendWindow:  uint32(tcpHdr.Window),
		SendUnacked: 0,
		AckChan:     make(chan uint32, 64),
		LastActive:  time.Now(),
		Created:     time.Now(),
	}
	conn.recvCond = sync.NewCond(&conn.mu)

	s.tcpConns.Store(key, conn)
	s.sendTCPSynAck(conn)

	go func() {
		tcpConn := newSimpleTCPConn(s, conn, key)
		dest := net.TCPDestination(dstIP, net.Port(tcpHdr.DstPort))
		s.handler.HandleConnection(tcpConn, dest)
	}()
}

// handleTCPFin processes connection close
func (s *stackSimple) handleTCPFin(conn *TCPConnection, tcpHdr *TCPHeader) {
	conn.LocalAck = tcpHdr.SeqNum + 1

	switch conn.State {
	case TCPStateEstablished:
		conn.State = TCPStateCloseWait
		s.sendTCPAck(conn)
		s.sendTCPFin(conn)
		conn.State = TCPStateLastAck
	case TCPStateFinWait1:
		conn.State = TCPStateClosing
		s.sendTCPAck(conn)
	case TCPStateFinWait2:
		conn.State = TCPStateTimeWait
		s.sendTCPAck(conn)
	}
}

// processUDP handles UDP datagrams
func (s *stackSimple) processUDP(srcIP, dstIP net.Address, payload []byte) {
	if len(payload) < 8 {
		return
	}

	udpHdr := parseUDPHeader(payload)
	if udpHdr == nil {
		return
	}

	udpData := payload[8:]
	if len(udpData) == 0 {
		return
	}

	src := net.UDPDestination(srcIP, net.Port(udpHdr.SrcPort))
	dst := net.UDPDestination(dstIP, net.Port(udpHdr.DstPort))

	key := ConnectionKey{
		SrcIP:   srcIP.String(),
		SrcPort: udpHdr.SrcPort,
		Proto:   ProtoUDP,
	}

	// Find or create UDP "connection"
	connVal, loaded := s.udpConns.LoadOrStore(key, &udpConn{
		handler: &udpConnectionHandler{
			writePacket: s.writeUDPPacket,
		},
		egress: make(chan []byte, 64),
		src:    src,
		dst:    dst,
	})

	conn := connVal.(*udpConn)

	if !loaded {
		// New connection, dispatch to handler
		go s.handler.HandleConnection(conn, dst)
	}

	// Queue the data
	select {
	case conn.egress <- udpData:
	default:
		// Drop if buffer full
	}
}

// cleanupLoop periodically removes idle connections
func (s *stackSimple) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			s.tcpConns.Range(func(key, value interface{}) bool {
				conn := value.(*TCPConnection)
				if now.Sub(conn.LastActive) > TCPIdleTimeout {
					conn.Close()
					s.tcpConns.Delete(key)
				}
				return true
			})
		}
	}
}

// ============================================================================
// Packet Parsing Functions
// ============================================================================

func parseIPv4Header(data []byte) *IPv4Header {
	if len(data) < 20 {
		return nil
	}

	hdr := &IPv4Header{
		Version:    data[0] >> 4,
		IHL:        data[0] & 0x0F,
		TOS:        data[1],
		TotalLen:   binary.BigEndian.Uint16(data[2:4]),
		ID:         binary.BigEndian.Uint16(data[4:6]),
		Flags:      data[6] >> 5,
		FragOffset: binary.BigEndian.Uint16(data[6:8]) & 0x1FFF,
		TTL:        data[8],
		Protocol:   data[9],
		Checksum:   binary.BigEndian.Uint16(data[10:12]),
	}
	copy(hdr.SrcIP[:], data[12:16])
	copy(hdr.DstIP[:], data[16:20])

	return hdr
}

func parseIPv6Header(data []byte) *IPv6Header {
	if len(data) < 40 {
		return nil
	}

	hdr := &IPv6Header{
		Version:      data[0] >> 4,
		TrafficClass: (data[0]&0x0F)<<4 | data[1]>>4,
		FlowLabel:    uint32(data[1]&0x0F)<<16 | uint32(data[2])<<8 | uint32(data[3]),
		PayloadLen:   binary.BigEndian.Uint16(data[4:6]),
		NextHeader:   data[6],
		HopLimit:     data[7],
	}
	copy(hdr.SrcIP[:], data[8:24])
	copy(hdr.DstIP[:], data[24:40])

	return hdr
}

func parseTCPHeader(data []byte) *TCPHeader {
	if len(data) < 20 {
		return nil
	}

	return &TCPHeader{
		SrcPort:    binary.BigEndian.Uint16(data[0:2]),
		DstPort:    binary.BigEndian.Uint16(data[2:4]),
		SeqNum:     binary.BigEndian.Uint32(data[4:8]),
		AckNum:     binary.BigEndian.Uint32(data[8:12]),
		DataOffset: data[12] >> 4,
		Flags:      data[13],
		Window:     binary.BigEndian.Uint16(data[14:16]),
		Checksum:   binary.BigEndian.Uint16(data[16:18]),
		UrgentPtr:  binary.BigEndian.Uint16(data[18:20]),
	}
}

func parseUDPHeader(data []byte) *UDPHeader {
	if len(data) < 8 {
		return nil
	}

	return &UDPHeader{
		SrcPort:  binary.BigEndian.Uint16(data[0:2]),
		DstPort:  binary.BigEndian.Uint16(data[2:4]),
		Length:   binary.BigEndian.Uint16(data[4:6]),
		Checksum: binary.BigEndian.Uint16(data[6:8]),
	}
}

// ============================================================================
// Packet Building and Sending Functions
// ============================================================================

func generateISN() uint32 {
	return uint32(time.Now().UnixNano() & 0xFFFFFFFF)
}

func (s *stackSimple) sendTCPSynAck(conn *TCPConnection) {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	flags := uint8(TCPFlagSYN | TCPFlagACK)
	s.sendTCPPacket(conn, flags, nil)
	conn.LocalSeq++
	conn.State = TCPStateSynReceived
}

func (s *stackSimple) sendTCPAck(conn *TCPConnection) {
	flags := uint8(TCPFlagACK)
	s.sendTCPPacket(conn, flags, nil)
}

func (s *stackSimple) sendTCPFin(conn *TCPConnection) {
	flags := uint8(TCPFlagFIN | TCPFlagACK)
	s.sendTCPPacket(conn, flags, nil)
	conn.LocalSeq++
}

func (s *stackSimple) sendTCPRst(srcIP, dstIP net.Address, tcpHdr *TCPHeader) {
	tcpLen := 20
	totalLen := 20 + tcpLen

	packet := make([]byte, totalLen)

	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(totalLen))
	packet[8] = 64
	packet[9] = ProtoTCP
	copy(packet[12:16], dstIP.IP())
	copy(packet[16:20], srcIP.IP())

	binary.BigEndian.PutUint16(packet[20:22], tcpHdr.DstPort)
	binary.BigEndian.PutUint16(packet[22:24], tcpHdr.SrcPort)
	binary.BigEndian.PutUint32(packet[24:28], tcpHdr.AckNum)
	binary.BigEndian.PutUint32(packet[28:32], tcpHdr.SeqNum+1)
	packet[32] = 0x50
	packet[33] = TCPFlagRST | TCPFlagACK

	s.setIPv4Checksum(packet[:20])
	s.setTCPChecksum(packet, 20)

	s.writePacket(packet)
}

func (s *stackSimple) sendTCPPacket(conn *TCPConnection, flags uint8, data []byte) {
	isIPv4 := conn.DstIP.Family().IsIPv4()

	tcpLen := 20 + len(data)
	var ipHdrLen int
	if isIPv4 {
		ipHdrLen = 20
	} else {
		ipHdrLen = 40
	}
	totalLen := ipHdrLen + tcpLen

	packet := make([]byte, totalLen)

	if isIPv4 {
		packet[0] = 0x45
		binary.BigEndian.PutUint16(packet[2:4], uint16(totalLen))
		packet[8] = 64
		packet[9] = ProtoTCP
		copy(packet[12:16], conn.DstIP.IP())
		copy(packet[16:20], conn.SrcIP.IP())
	} else {
		packet[0] = 0x60
		binary.BigEndian.PutUint16(packet[4:6], uint16(tcpLen))
		packet[6] = ProtoTCP
		packet[7] = 64
		copy(packet[8:24], conn.DstIP.IP())
		copy(packet[24:40], conn.SrcIP.IP())
	}

	tcpStart := ipHdrLen
	binary.BigEndian.PutUint16(packet[tcpStart:tcpStart+2], conn.DstPort)
	binary.BigEndian.PutUint16(packet[tcpStart+2:tcpStart+4], conn.SrcPort)
	binary.BigEndian.PutUint32(packet[tcpStart+4:tcpStart+8], conn.LocalSeq)
	binary.BigEndian.PutUint32(packet[tcpStart+8:tcpStart+12], conn.LocalAck)
	packet[tcpStart+12] = 0x50
	packet[tcpStart+13] = flags
	binary.BigEndian.PutUint16(packet[tcpStart+14:tcpStart+16], 65535)

	if len(data) > 0 {
		copy(packet[tcpStart+20:], data)
	}

	if isIPv4 {
		s.setIPv4Checksum(packet[:20])
	}
	s.setTCPChecksum(packet, tcpStart)

	s.writePacket(packet)
}

func (s *stackSimple) writeUDPPacket(data []byte, src, dst net.Destination) error {
	isIPv4 := src.Address.Family().IsIPv4()

	udpLen := 8 + len(data)
	var ipHdrLen int
	if isIPv4 {
		ipHdrLen = 20
	} else {
		ipHdrLen = 40
	}
	totalLen := ipHdrLen + udpLen

	packet := make([]byte, totalLen)

	if isIPv4 {
		packet[0] = 0x45
		binary.BigEndian.PutUint16(packet[2:4], uint16(totalLen))
		packet[8] = 64
		packet[9] = ProtoUDP
		copy(packet[12:16], src.Address.IP())
		copy(packet[16:20], dst.Address.IP())
	} else {
		packet[0] = 0x60
		binary.BigEndian.PutUint16(packet[4:6], uint16(udpLen))
		packet[6] = ProtoUDP
		packet[7] = 64
		copy(packet[8:24], src.Address.IP())
		copy(packet[24:40], dst.Address.IP())
	}

	udpStart := ipHdrLen
	binary.BigEndian.PutUint16(packet[udpStart:udpStart+2], uint16(src.Port))
	binary.BigEndian.PutUint16(packet[udpStart+2:udpStart+4], uint16(dst.Port))
	binary.BigEndian.PutUint16(packet[udpStart+4:udpStart+6], uint16(udpLen))

	copy(packet[udpStart+8:], data)

	if isIPv4 {
		s.setIPv4Checksum(packet[:20])
	}
	s.setUDPChecksum(packet, udpStart)

	return s.writePacket(packet)
}

func (s *stackSimple) writePacket(packet []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	buf, err := s.tun.session.AllocateSendPacket(len(packet))
	if err != nil {
		return err
	}

	copy(buf, packet)
	s.tun.session.SendPacket(buf)

	return nil
}

func (s *stackSimple) setIPv4Checksum(header []byte) {
	header[10] = 0
	header[11] = 0

	var sum uint32
	for i := 0; i < len(header); i += 2 {
		sum += uint32(header[i])<<8 | uint32(header[i+1])
	}
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	checksum := ^uint16(sum)
	binary.BigEndian.PutUint16(header[10:12], checksum)
}

func (s *stackSimple) setTCPChecksum(packet []byte, tcpStart int) {
	packet[tcpStart+16] = 0
	packet[tcpStart+17] = 0

	tcpLen := len(packet) - tcpStart
	isIPv4 := (packet[0] >> 4) == 4

	var sum uint32

	if isIPv4 {
		sum += uint32(packet[12])<<8 | uint32(packet[13])
		sum += uint32(packet[14])<<8 | uint32(packet[15])
		sum += uint32(packet[16])<<8 | uint32(packet[17])
		sum += uint32(packet[18])<<8 | uint32(packet[19])
	} else {
		for i := 8; i < 24; i += 2 {
			sum += uint32(packet[i])<<8 | uint32(packet[i+1])
		}
		for i := 24; i < 40; i += 2 {
			sum += uint32(packet[i])<<8 | uint32(packet[i+1])
		}
	}
	sum += uint32(ProtoTCP)
	sum += uint32(tcpLen)

	for i := tcpStart; i < len(packet)-1; i += 2 {
		sum += uint32(packet[i])<<8 | uint32(packet[i+1])
	}
	if (len(packet)-tcpStart)%2 != 0 {
		sum += uint32(packet[len(packet)-1]) << 8
	}

	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	checksum := ^uint16(sum)
	binary.BigEndian.PutUint16(packet[tcpStart+16:tcpStart+18], checksum)
}

func (s *stackSimple) setUDPChecksum(packet []byte, udpStart int) {
	packet[udpStart+6] = 0
	packet[udpStart+7] = 0

	udpLen := len(packet) - udpStart
	isIPv4 := (packet[0] >> 4) == 4

	var sum uint32

	if isIPv4 {
		sum += uint32(packet[12])<<8 | uint32(packet[13])
		sum += uint32(packet[14])<<8 | uint32(packet[15])
		sum += uint32(packet[16])<<8 | uint32(packet[17])
		sum += uint32(packet[18])<<8 | uint32(packet[19])
	} else {
		for i := 8; i < 24; i += 2 {
			sum += uint32(packet[i])<<8 | uint32(packet[i+1])
		}
		for i := 24; i < 40; i += 2 {
			sum += uint32(packet[i])<<8 | uint32(packet[i+1])
		}
	}
	sum += uint32(ProtoUDP)
	sum += uint32(udpLen)

	for i := udpStart; i < len(packet)-1; i += 2 {
		sum += uint32(packet[i])<<8 | uint32(packet[i+1])
	}
	if (len(packet)-udpStart)%2 != 0 {
		sum += uint32(packet[len(packet)-1]) << 8
	}

	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	checksum := ^uint16(sum)
	if checksum == 0 {
		checksum = 0xFFFF
	}
	binary.BigEndian.PutUint16(packet[udpStart+6:udpStart+8], checksum)
}

// ============================================================================
// TCP Connection Wrapper - implements net.Conn
// ============================================================================

type simpleTCPConn struct {
	stack  *stackSimple
	conn   *TCPConnection
	key    ConnectionKey
	closed bool
}

func newSimpleTCPConn(stack *stackSimple, conn *TCPConnection, key ConnectionKey) *simpleTCPConn {
	conn.mu.Lock()
	conn.State = TCPStateEstablished
	conn.mu.Unlock()

	return &simpleTCPConn{
		stack: stack,
		conn:  conn,
		key:   key,
	}
}

func (c *simpleTCPConn) Read(b []byte) (int, error) {
	c.conn.mu.Lock()
	defer c.conn.mu.Unlock()

	// Wait for data if buffer is empty
	for c.conn.recvBuffer.Len() == 0 && !c.conn.closed {
		c.conn.recvCond.Wait()
	}

	if c.conn.closed && c.conn.recvBuffer.Len() == 0 {
		return 0, errors.New("connection closed")
	}

	// Read directly from buffer
	return c.conn.recvBuffer.Read(b)
}

func (c *simpleTCPConn) Write(b []byte) (int, error) {
	if c.closed {
		return 0, errors.New("connection closed")
	}

	const maxSegment = 1400

	sent := 0
	for sent < len(b) {
		end := sent + maxSegment
		if end > len(b) {
			end = len(b)
		}
		chunk := b[sent:end]

		c.conn.mu.Lock()
		c.stack.sendTCPPacket(c.conn, TCPFlagACK|TCPFlagPSH, chunk)
		c.conn.LocalSeq += uint32(len(chunk))
		c.conn.mu.Unlock()

		sent += len(chunk)
	}

	return len(b), nil
}

func (c *simpleTCPConn) Close() error {
	if c.closed {
		return nil
	}
	c.closed = true

	c.conn.mu.Lock()
	if c.conn.State == TCPStateEstablished {
		c.conn.State = TCPStateFinWait1
		c.stack.sendTCPFin(c.conn)
	}
	c.conn.mu.Unlock()

	c.stack.tcpConns.Delete(c.key)
	return nil
}

func (c *simpleTCPConn) LocalAddr() net.Addr {
	return &net.TCPAddr{
		IP:   c.conn.DstIP.IP(),
		Port: int(c.conn.DstPort),
	}
}

func (c *simpleTCPConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{
		IP:   c.conn.SrcIP.IP(),
		Port: int(c.conn.SrcPort),
	}
}

func (c *simpleTCPConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *simpleTCPConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *simpleTCPConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func (c *TCPConnection) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}
	c.closed = true

	// Wake up any waiting readers
	c.recvCond.Broadcast()

	return nil
}
