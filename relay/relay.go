package relay

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
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

type UDPProxyServer struct {
	addr          string
	serverURL     string
	conn          *net.UDPConn
	proxyMappings sync.Map // map[string]ProxyMapping where key is "ip:port"
	connections   sync.Map // map[string]*DestinationConn where key is destination "ip:port"
	publicKey     wgtypes.Key
}

type Logger interface {
	Info(format string, args ...interface{})
	Error(format string, args ...interface{})
	Fatal(format string, args ...interface{})
}

func NewUDPProxyServer(addr, serverURL string, publicKey wgtypes.Key) *UDPProxyServer {
	return &UDPProxyServer{
		addr:      addr,
		serverURL: serverURL,
		publicKey: publicKey,
	}
}

func (s *UDPProxyServer) Start() error {
	// First fetch initial mappings
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

	go s.handlePackets()
	go s.cleanupIdleConnections()
	return nil
}

func (s *UDPProxyServer) Stop() {
	s.conn.Close()
}

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

	// Store all mappings in our sync.Map
	for key, mapping := range initialMappings.Mappings {
		s.proxyMappings.Store(key, mapping)
	}

	logger.Info("Loaded %d initial proxy mappings", len(initialMappings.Mappings))
	return nil
}

func (s *UDPProxyServer) handlePackets() {
	buffer := make([]byte, 1500) // Standard MTU size
	for {
		n, remoteAddr, err := s.conn.ReadFromUDP(buffer)
		if err != nil {
			logger.Error("Error reading UDP packet: %v", err)
			continue
		}

		// Otherwise, treat it as an incoming WireGuard or Hole Punch request
		if n > 0 && buffer[0] >= 1 && buffer[0] <= 4 {
			go s.handleWireGuardPacket(buffer[:n], remoteAddr)
			continue
		}

		// Try to handle as hole punch message
		var msg HolePunchMessage
		if err := json.Unmarshal(buffer[:n], &msg); err != nil {
			logger.Error("Error unmarshaling message: %v", err)
			continue
		}

		endpoint := ClientEndpoint{
			OlmID:     msg.OlmID,
			NewtID:    msg.NewtID,
			IP:        remoteAddr.IP.String(),
			Port:      remoteAddr.Port,
			Timestamp: time.Now().Unix(),
		}

		go s.notifyServer(endpoint)
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

	// Get or create a connection to the destination
	conn, err := s.getOrCreateConnection(destAddr, remoteAddr)
	if err != nil {
		logger.Error("Failed to get/create connection: %v", err)
		return
	}

	// Forward the packet
	_, err = conn.Write(packet)
	if err != nil {
		logger.Error("Failed to proxy packet: %v", err)
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
	key := net.JoinHostPort(sourceIP, string(sourcePort))
	mapping := ProxyMapping{
		DestinationIP:   destinationIP,
		DestinationPort: destinationPort,
	}
	s.proxyMappings.Store(key, mapping)
}
