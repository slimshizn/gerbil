package relay

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/fosrl/gerbil/logger"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type HolePunchMessage struct {
	OlmID  string `json:"olmId"`
	NewtID string `json:"newtId"`
}

type ClientEndpoint struct {
	OlmID     string `json:"olmId"`
	NewtID    string `json:"newtId"`
	IP        string `json:"ip"`
	Port      int    `json:"port"`
	Timestamp int64  `json:"timestamp"`
}

type ProxyMapping struct {
	DestinationIP   string `json:"destinationIP"`
	DestinationPort int    `json:"destinationPort"`
}

type DestinationConn struct {
	conn     *net.UDPConn
	lastUsed time.Time
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

// --- End Types ---

// bufferPool allows reusing buffers to reduce allocations.
var bufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 1500)
	},
}

// UDPProxyServer now has a channel for incoming packets.
type UDPProxyServer struct {
	addr          string
	serverURL     string
	conn          *net.UDPConn
	proxyMappings sync.Map // map[string]ProxyMapping where key is "ip:port"
	connections   sync.Map // map[string]*DestinationConn where key is destination "ip:port"
	publicKey     wgtypes.Key
	packetChan    chan Packet
}

// NewUDPProxyServer initializes the server with a buffered packet channel.
func NewUDPProxyServer(addr, serverURL string, publicKey wgtypes.Key) *UDPProxyServer {
	return &UDPProxyServer{
		addr:       addr,
		serverURL:  serverURL,
		publicKey:  publicKey,
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
			// Process as a hole punch message.
			var msg HolePunchMessage
			if err := json.Unmarshal(packet.data, &msg); err != nil {
				logger.Error("Error unmarshaling message: %v", err)
			} else {
				endpoint := ClientEndpoint{
					OlmID:     msg.OlmID,
					NewtID:    msg.NewtID,
					IP:        packet.remoteAddr.IP.String(),
					Port:      packet.remoteAddr.Port,
					Timestamp: time.Now().Unix(),
				}
				// You can call notifyServer synchronously here or dispatch further if needed.
				s.notifyServer(endpoint)
			}
		}
		// Return the buffer to the pool for reuse.
		bufferPool.Put(packet.data[:1500])
	}
}

// --- The remaining methods remain largely the same ---
// For example: fetchInitialMappings, handleWireGuardPacket, getOrCreateConnection, etc.

func (s *UDPProxyServer) fetchInitialMappings() error {
	body := bytes.NewBuffer([]byte(fmt.Sprintf(`{"publicKey": "%s"}`, s.publicKey.PublicKey().String())))
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

// Example handleWireGuardPacket remains unchanged.
func (s *UDPProxyServer) handleWireGuardPacket(packet []byte, remoteAddr *net.UDPAddr) {
	key := remoteAddr.String()
	mapping, ok := s.proxyMappings.Load(key)
	if !ok {
		logger.Error("No proxy mapping found for %s", key)
		return
	}
	proxyMapping := mapping.(ProxyMapping)
	destAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d",
		proxyMapping.DestinationIP, proxyMapping.DestinationPort))
	if err != nil {
		logger.Error("Failed to resolve destination address: %v", err)
		return
	}
	conn, err := s.getOrCreateConnection(destAddr, remoteAddr)
	if err != nil {
		logger.Error("Failed to get/create connection: %v", err)
		return
	}
	_, err = conn.Write(packet)
	if err != nil {
		logger.Error("Failed to proxy packet: %v", err)
	}
}

func (s *UDPProxyServer) getOrCreateConnection(destAddr *net.UDPAddr, remoteAddr *net.UDPAddr) (*net.UDPConn, error) {
	key := remoteAddr.String()

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

	// Store the mapping
	key := fmt.Sprintf("%s:%d", endpoint.IP, endpoint.Port)
	s.proxyMappings.Store(key, mapping)

	logger.Debug("Stored proxy mapping for %s: %v", key, mapping)
}

func (s *UDPProxyServer) UpdateProxyMapping(sourceIP string, sourcePort int,
	destinationIP string, destinationPort int) {
	key := net.JoinHostPort(sourceIP, strconv.Itoa(sourcePort))
	mapping := ProxyMapping{
		DestinationIP:   destinationIP,
		DestinationPort: destinationPort,
	}
	s.proxyMappings.Store(key, mapping)
}
