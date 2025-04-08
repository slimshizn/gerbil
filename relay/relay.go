package relay

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/fosrl/gerbil/logger"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type EncryptedHolePunchMessage struct {
	EphemeralPublicKey string `json:"ephemeralPublicKey"`
	Nonce              []byte `json:"nonce"`
	Ciphertext         []byte `json:"ciphertext"`
}

type HolePunchMessage struct {
	OlmID  string `json:"olmId"`
	NewtID string `json:"newtId"`
	Token  string `json:"token"`
}

type ClientEndpoint struct {
	OlmID     string `json:"olmId"`
	NewtID    string `json:"newtId"`
	Token     string `json:"token"`
	IP        string `json:"ip"`
	Port      int    `json:"port"`
	Timestamp int64  `json:"timestamp"`
}

// Updated to support multiple destination peers
type ProxyMapping struct {
	Destinations []PeerDestination `json:"destinations"`
}

type PeerDestination struct {
	DestinationIP   string `json:"destinationIP"`
	DestinationPort int    `json:"destinationPort"`
}

type DestinationConn struct {
	conn     *net.UDPConn
	lastUsed time.Time
}

// Type for storing WireGuard handshake information
type WireGuardSession struct {
	ReceiverIndex uint32
	SenderIndex   uint32
	DestAddr      *net.UDPAddr
	LastSeen      time.Time
}

type InitialMappings struct {
	Mappings map[string]ProxyMapping `json:"mappings"` // key is "ip:port"
}

// Packet is a simple struct to hold the packet data and sender info.
type Packet struct {
	data       []byte
	remoteAddr *net.UDPAddr
	n          int
}

// WireGuard message types
const (
	WireGuardMessageTypeHandshakeInitiation = 1
	WireGuardMessageTypeHandshakeResponse   = 2
	WireGuardMessageTypeCookieReply         = 3
	WireGuardMessageTypeTransportData       = 4
)

// --- End Types ---

// bufferPool allows reusing buffers to reduce allocations.
var bufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 1500)
	},
}

// UDPProxyServer has a channel for incoming packets.
type UDPProxyServer struct {
	addr          string
	serverURL     string
	conn          *net.UDPConn
	proxyMappings sync.Map // map[string]ProxyMapping where key is "ip:port"
	connections   sync.Map // map[string]*DestinationConn where key is destination "ip:port"
	privateKey    wgtypes.Key
	packetChan    chan Packet

	// Session tracking for WireGuard peers
	// Key format: "senderIndex:receiverIndex"
	wgSessions sync.Map
}

// NewUDPProxyServer initializes the server with a buffered packet channel.
func NewUDPProxyServer(addr, serverURL string, privateKey wgtypes.Key) *UDPProxyServer {
	return &UDPProxyServer{
		addr:       addr,
		serverURL:  serverURL,
		privateKey: privateKey,
		packetChan: make(chan Packet, 1000),
	}
}

// Start sets up the UDP listener, worker pool, and begins reading packets.
func (s *UDPProxyServer) Start() error {
	// Fetch initial mappings.
	if err := s.fetchInitialMappings(); err != nil {
		return fmt.Errorf("failed to fetch initial mappings: %v", err)
	}

	udpAddr, err := net.ResolveUDPAddr("udp", s.addr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	s.conn = conn
	logger.Info("UDP server listening on %s", s.addr)

	// Start a fixed number of worker goroutines.
	workerCount := 10 // TODO: Make this configurable or pick it better!
	for i := 0; i < workerCount; i++ {
		go s.packetWorker()
	}

	// Start the goroutine that reads packets from the UDP socket.
	go s.readPackets()

	// Start the idle connection cleanup routine.
	go s.cleanupIdleConnections()

	// Start the session cleanup routine
	go s.cleanupIdleSessions()

	return nil
}

func (s *UDPProxyServer) Stop() {
	s.conn.Close()
}

// readPackets continuously reads from the UDP socket and pushes packets into the channel.
func (s *UDPProxyServer) readPackets() {
	for {
		buf := bufferPool.Get().([]byte)
		n, remoteAddr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			logger.Error("Error reading UDP packet: %v", err)
			continue
		}
		s.packetChan <- Packet{data: buf[:n], remoteAddr: remoteAddr, n: n}
	}
}

// packetWorker processes incoming packets from the channel.
func (s *UDPProxyServer) packetWorker() {
	for packet := range s.packetChan {
		// Determine packet type by inspecting the first byte.
		if packet.n > 0 && packet.data[0] >= 1 && packet.data[0] <= 4 {
			// Process as a WireGuard packet.
			s.handleWireGuardPacket(packet.data, packet.remoteAddr)
		} else {
			// Process as an encrypted hole punch message
			var encMsg EncryptedHolePunchMessage
			if err := json.Unmarshal(packet.data, &encMsg); err != nil {
				logger.Error("Error unmarshaling encrypted message: %v", err)
				// Return the buffer to the pool for reuse and continue with next packet
				bufferPool.Put(packet.data[:1500])
				continue
			}

			if encMsg.EphemeralPublicKey == "" {
				logger.Error("Received malformed message without ephemeral key")
				// Return the buffer to the pool for reuse and continue with next packet
				bufferPool.Put(packet.data[:1500])
				continue
			}

			// This appears to be an encrypted message
			decryptedData, err := s.decryptMessage(encMsg)
			if err != nil {
				logger.Error("Failed to decrypt message: %v", err)
				// Return the buffer to the pool for reuse and continue with next packet
				bufferPool.Put(packet.data[:1500])
				continue
			}

			// Process the decrypted hole punch message
			var msg HolePunchMessage
			if err := json.Unmarshal(decryptedData, &msg); err != nil {
				logger.Error("Error unmarshaling decrypted message: %v", err)
				// Return the buffer to the pool for reuse and continue with next packet
				bufferPool.Put(packet.data[:1500])
				continue
			}

			endpoint := ClientEndpoint{
				NewtID:    msg.NewtID,
				OlmID:     msg.OlmID,
				Token:     msg.Token,
				IP:        packet.remoteAddr.IP.String(),
				Port:      packet.remoteAddr.Port,
				Timestamp: time.Now().Unix(),
			}
			s.notifyServer(endpoint)
		}
		// Return the buffer to the pool for reuse.
		bufferPool.Put(packet.data[:1500])
	}
}

// decryptMessage decrypts the message using the server's private key
func (s *UDPProxyServer) decryptMessage(encMsg EncryptedHolePunchMessage) ([]byte, error) {
	// Parse the ephemeral public key
	ephPubKey, err := wgtypes.ParseKey(encMsg.EphemeralPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ephemeral public key: %v", err)
	}

	// Use X25519 for key exchange instead of ScalarMult
	sharedSecret, err := curve25519.X25519(s.privateKey[:], ephPubKey[:])
	if err != nil {
		return nil, fmt.Errorf("failed to perform X25519 key exchange: %v", err)
	}

	// Create the AEAD cipher using the shared secret
	aead, err := chacha20poly1305.New(sharedSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to create AEAD cipher: %v", err)
	}

	// Verify nonce size
	if len(encMsg.Nonce) != aead.NonceSize() {
		return nil, fmt.Errorf("invalid nonce size")
	}

	// Decrypt the ciphertext
	plaintext, err := aead.Open(nil, encMsg.Nonce, encMsg.Ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt message: %v", err)
	}

	return plaintext, nil
}

func (s *UDPProxyServer) fetchInitialMappings() error {
	body := bytes.NewBuffer([]byte(fmt.Sprintf(`{"publicKey": "%s"}`, s.privateKey.PublicKey().String())))
	resp, err := http.Post(s.serverURL+"/gerbil/get-all-relays", "application/json", body)
	if err != nil {
		return fmt.Errorf("failed to fetch mappings: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned non-OK status: %d, body: %s",
			resp.StatusCode, string(body))
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %v", err)
	}
	logger.Info("Received initial mappings: %s", string(data))
	var initialMappings InitialMappings
	if err := json.Unmarshal(data, &initialMappings); err != nil {
		return fmt.Errorf("failed to unmarshal initial mappings: %v", err)
	}
	// Store mappings in our sync.Map.
	for key, mapping := range initialMappings.Mappings {
		s.proxyMappings.Store(key, mapping)
	}
	logger.Info("Loaded %d initial proxy mappings", len(initialMappings.Mappings))
	return nil
}

// Extract WireGuard message indices
func extractWireGuardIndices(packet []byte) (uint32, uint32, bool) {
	if len(packet) < 12 {
		return 0, 0, false
	}

	messageType := packet[0]
	if messageType == WireGuardMessageTypeHandshakeInitiation {
		// Handshake initiation: extract sender index at offset 4
		senderIndex := binary.LittleEndian.Uint32(packet[4:8])
		return 0, senderIndex, true
	} else if messageType == WireGuardMessageTypeHandshakeResponse {
		// Handshake response: extract sender index at offset 4 and receiver index at offset 8
		senderIndex := binary.LittleEndian.Uint32(packet[4:8])
		receiverIndex := binary.LittleEndian.Uint32(packet[8:12])
		return receiverIndex, senderIndex, true
	} else if messageType == WireGuardMessageTypeTransportData {
		// Transport data: extract receiver index at offset 4
		receiverIndex := binary.LittleEndian.Uint32(packet[4:8])
		return receiverIndex, 0, true
	}

	return 0, 0, false
}

// Updated to handle multi-peer WireGuard communication
func (s *UDPProxyServer) handleWireGuardPacket(packet []byte, remoteAddr *net.UDPAddr) {
	if len(packet) == 0 {
		logger.Error("Received empty packet")
		return
	}

	messageType := packet[0]
	receiverIndex, senderIndex, ok := extractWireGuardIndices(packet)

	if !ok {
		logger.Error("Failed to extract WireGuard indices")
		return
	}

	key := remoteAddr.String()
	mappingObj, ok := s.proxyMappings.Load(key)
	if !ok {
		logger.Error("No proxy mapping found for %s", key)
		return
	}

	proxyMapping := mappingObj.(ProxyMapping)

	// Handle different WireGuard message types
	switch messageType {
	case WireGuardMessageTypeHandshakeInitiation:
		// Initial handshake: forward to all peers
		logger.Debug("Forwarding handshake initiation from %s (sender index: %d)", remoteAddr, senderIndex)

		for _, dest := range proxyMapping.Destinations {
			destAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", dest.DestinationIP, dest.DestinationPort))
			if err != nil {
				logger.Error("Failed to resolve destination address: %v", err)
				continue
			}

			conn, err := s.getOrCreateConnection(destAddr, remoteAddr)
			if err != nil {
				logger.Error("Failed to get/create connection: %v", err)
				continue
			}

			_, err = conn.Write(packet)
			if err != nil {
				logger.Error("Failed to forward handshake initiation: %v", err)
			}
		}

	case WireGuardMessageTypeHandshakeResponse:
		// Received handshake response: establish session mapping
		logger.Debug("Received handshake response with receiver index %d and sender index %d from %s",
			receiverIndex, senderIndex, remoteAddr)

		// Create a session key for the peer that sent the initial handshake
		sessionKey := fmt.Sprintf("%d:%d", receiverIndex, senderIndex)

		// Store the session information
		s.wgSessions.Store(sessionKey, &WireGuardSession{
			ReceiverIndex: receiverIndex,
			SenderIndex:   senderIndex,
			DestAddr:      remoteAddr,
			LastSeen:      time.Now(),
		})

		// Forward the response to the original sender
		for _, dest := range proxyMapping.Destinations {
			destAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", dest.DestinationIP, dest.DestinationPort))
			if err != nil {
				logger.Error("Failed to resolve destination address: %v", err)
				continue
			}

			conn, err := s.getOrCreateConnection(destAddr, remoteAddr)
			if err != nil {
				logger.Error("Failed to get/create connection: %v", err)
				continue
			}

			_, err = conn.Write(packet)
			if err != nil {
				logger.Error("Failed to forward handshake response: %v", err)
			}
		}

	case WireGuardMessageTypeTransportData:
		// Data packet: forward only to the established session peer
		logger.Debug("Received transport data with receiver index %d from %s", receiverIndex, remoteAddr)

		// Look up the session based on the receiver index
		var destAddr *net.UDPAddr

		// First check for existing sessions to see if we know where to send this packet
		s.wgSessions.Range(func(k, v interface{}) bool {
			session := v.(*WireGuardSession)
			if session.SenderIndex == receiverIndex {
				// Found matching session
				destAddr = session.DestAddr

				// Update last seen time
				session.LastSeen = time.Now()
				s.wgSessions.Store(k, session)
				return false // stop iteration
			}
			return true // continue iteration
		})

		if destAddr != nil {
			// We found a specific peer to forward to
			conn, err := s.getOrCreateConnection(destAddr, remoteAddr)
			if err != nil {
				logger.Error("Failed to get/create connection: %v", err)
				return
			}

			_, err = conn.Write(packet)
			if err != nil {
				logger.Error("Failed to forward transport data: %v", err)
			}
		} else {
			// No known session, fall back to forwarding to all peers
			logger.Debug("No session found for receiver index %d, forwarding to all destinations", receiverIndex)
			for _, dest := range proxyMapping.Destinations {
				destAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", dest.DestinationIP, dest.DestinationPort))
				if err != nil {
					logger.Error("Failed to resolve destination address: %v", err)
					continue
				}

				conn, err := s.getOrCreateConnection(destAddr, remoteAddr)
				if err != nil {
					logger.Error("Failed to get/create connection: %v", err)
					continue
				}

				_, err = conn.Write(packet)
				if err != nil {
					logger.Error("Failed to forward transport data: %v", err)
				}
			}
		}

	default:
		// Other packet types (like cookie reply)
		logger.Debug("Forwarding WireGuard packet type %d from %s", messageType, remoteAddr)

		// Forward to all peers
		for _, dest := range proxyMapping.Destinations {
			destAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", dest.DestinationIP, dest.DestinationPort))
			if err != nil {
				logger.Error("Failed to resolve destination address: %v", err)
				continue
			}

			conn, err := s.getOrCreateConnection(destAddr, remoteAddr)
			if err != nil {
				logger.Error("Failed to get/create connection: %v", err)
				continue
			}

			_, err = conn.Write(packet)
			if err != nil {
				logger.Error("Failed to forward WireGuard packet: %v", err)
			}
		}
	}
}

func (s *UDPProxyServer) getOrCreateConnection(destAddr *net.UDPAddr, remoteAddr *net.UDPAddr) (*net.UDPConn, error) {
	key := destAddr.String() + "-" + remoteAddr.String()

	// Check if we have an existing connection
	if conn, ok := s.connections.Load(key); ok {
		destConn := conn.(*DestinationConn)
		destConn.lastUsed = time.Now()
		return destConn.conn, nil
	}

	// Create new connection
	newConn, err := net.DialUDP("udp", nil, destAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to create UDP connection: %v", err)
	}

	// Store the new connection
	s.connections.Store(key, &DestinationConn{
		conn:     newConn,
		lastUsed: time.Now(),
	})

	// Start a goroutine to handle responses
	go s.handleResponses(newConn, destAddr, remoteAddr)

	return newConn, nil
}

func (s *UDPProxyServer) handleResponses(conn *net.UDPConn, destAddr *net.UDPAddr, remoteAddr *net.UDPAddr) {
	buffer := make([]byte, 1500)
	for {
		n, err := conn.Read(buffer)
		if err != nil {
			logger.Error("Error reading response from %s: %v", destAddr.String(), err)
			return
		}

		// Process the response to track sessions if it's a WireGuard packet
		if n > 0 && buffer[0] >= 1 && buffer[0] <= 4 {
			receiverIndex, senderIndex, ok := extractWireGuardIndices(buffer[:n])
			if ok && buffer[0] == WireGuardMessageTypeHandshakeResponse {
				// Store the session mapping for the handshake response
				sessionKey := fmt.Sprintf("%d:%d", senderIndex, receiverIndex)
				s.wgSessions.Store(sessionKey, &WireGuardSession{
					ReceiverIndex: receiverIndex,
					SenderIndex:   senderIndex,
					DestAddr:      destAddr,
					LastSeen:      time.Now(),
				})
				logger.Debug("Stored session mapping: %s -> %s", sessionKey, destAddr.String())
			}
		}

		// Forward the response back through the main listener
		_, err = s.conn.WriteToUDP(buffer[:n], remoteAddr)
		if err != nil {
			logger.Error("Failed to forward response: %v", err)
		}
	}
}

// Add a cleanup method to periodically remove idle connections
func (s *UDPProxyServer) cleanupIdleConnections() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		now := time.Now()
		s.connections.Range(func(key, value interface{}) bool {
			destConn := value.(*DestinationConn)
			if now.Sub(destConn.lastUsed) > 10*time.Minute {
				destConn.conn.Close()
				s.connections.Delete(key)
			}
			return true
		})
	}
}

// New method to periodically remove idle sessions
func (s *UDPProxyServer) cleanupIdleSessions() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		now := time.Now()
		s.wgSessions.Range(func(key, value interface{}) bool {
			session := value.(*WireGuardSession)
			if now.Sub(session.LastSeen) > 15*time.Minute {
				s.wgSessions.Delete(key)
				logger.Debug("Removed idle session: %s", key)
			}
			return true
		})
	}
}

func (s *UDPProxyServer) notifyServer(endpoint ClientEndpoint) {
	jsonData, err := json.Marshal(endpoint)
	if err != nil {
		logger.Error("Failed to marshal endpoint data: %v", err)
		return
	}

	resp, err := http.Post(s.serverURL+"/gerbil/update-hole-punch", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		logger.Error("Failed to notify server: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		logger.Error("Server returned non-OK status: %d, body: %s",
			resp.StatusCode, string(body))
		return
	}

	// Parse the proxy mapping response
	var mapping ProxyMapping
	if err := json.NewDecoder(resp.Body).Decode(&mapping); err != nil {
		logger.Error("Failed to decode proxy mapping: %v", err)
		return
	}

	logger.Debug("Received proxy mapping: %v", mapping)

	// Store the mapping
	key := fmt.Sprintf("%s:%d", endpoint.IP, endpoint.Port)
	s.proxyMappings.Store(key, mapping)

	logger.Debug("Stored proxy mapping for %s with %d destinations", key, len(mapping.Destinations))
}

// Updated to support multiple destinations
func (s *UDPProxyServer) UpdateProxyMapping(sourceIP string, sourcePort int, destinations []PeerDestination) {
	key := net.JoinHostPort(sourceIP, strconv.Itoa(sourcePort))
	mapping := ProxyMapping{
		Destinations: destinations,
	}
	s.proxyMappings.Store(key, mapping)
}
