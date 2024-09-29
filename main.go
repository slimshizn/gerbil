package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var (
	interfaceName = "wg0"
	listenAddr    = ":8080"
)

type WgConfig struct {
	PrivateKey string `json:"privateKey"`
	ListenPort int    `json:"listenPort"`
	IpAddress  string `json:"ipAddress"`
	Peers      []Peer `json:"peers"`
}

type Peer struct {
	PublicKey  string   `json:"publicKey"`
	AllowedIPs []string `json:"allowedIps"`
}

type PeerBandwidth struct {
	PublicKey string  `json:"publicKey"`
	BytesIn   float64 `json:"bytesIn"`
	BytesOut  float64 `json:"bytesOut"`
}

var (
	wgClient *wgctrl.Client
)

func main() {
	var err error
	var wgconfig WgConfig

	// Define command line flags
	interfaceNameArg := flag.String("interface", "wg0", "Name of the WireGuard interface")
	configFile := flag.String("config", "", "Path to local configuration file")
	remoteConfigURL := flag.String("remoteConfig", "", "URL to fetch remote configuration")
	listenAddrArg := flag.String("listen", ":8080", "Address to listen on")
	reportBandwidthTo := flag.String("reportBandwidthTo", "", "Address to listen on")
	flag.Parse()

	if *interfaceNameArg != "" {
		interfaceName = *interfaceNameArg
	}
	if *listenAddrArg != "" {
		listenAddr = *listenAddrArg
	}

	// Validate that only one config option is provided
	if (*configFile != "" && *remoteConfigURL != "") || (*configFile == "" && *remoteConfigURL == "") {
		log.Fatal("Please provide either --config or --remoteConfig, but not both")
	}

	wgClient, err = wgctrl.New()
	if err != nil {
		log.Fatalf("Failed to create WireGuard client: %v", err)
	}
	defer wgClient.Close()

	// Load configuration based on provided argument
	if *configFile != "" {
		wgconfig, err = loadConfig(*configFile)
	} else {
		wgconfig, err = loadRemoteConfig(*remoteConfigURL)
	}

	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Ensure the WireGuard interface exists and is configured
	if err := ensureWireguardInterface(wgconfig); err != nil {
		log.Fatalf("Failed to ensure WireGuard interface: %v", err)
	}

	// Ensure the WireGuard peers exist
	ensureWireguardPeers(wgconfig.Peers)

	if *reportBandwidthTo != "" {
		go periodicBandwidthCheck(*reportBandwidthTo)
	}

	http.HandleFunc("/peer", handlePeer)
	log.Printf("Starting server on %s", listenAddr)
	log.Fatal(http.ListenAndServe(listenAddr, nil))
}

func loadRemoteConfig(url string) (WgConfig, error) {
	resp, err := http.Get(url)
	if err != nil {
		return WgConfig{}, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return WgConfig{}, err
	}

	var config WgConfig
	err = json.Unmarshal(data, &config)
	return config, err
}

func loadConfig(filename string) (WgConfig, error) {
	// Open the JSON file
	file, err := os.Open(filename)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return WgConfig{}, err
	}
	defer file.Close()

	// Read the file contents
	byteValue, err := io.ReadAll(file)
	if err != nil {
		fmt.Println("Error reading file:", err)
		return WgConfig{}, err
	}

	// Create a variable of the appropriate type to hold the unmarshaled data
	var wgconfig WgConfig

	// Unmarshal the JSON data into the struct
	err = json.Unmarshal(byteValue, &wgconfig)
	if err != nil {
		fmt.Println("Error unmarshaling JSON:", err)
		return WgConfig{}, err
	}

	return wgconfig, nil
}

func ensureWireguardInterface(wgconfig WgConfig) error {
	// Check if the WireGuard interface exists
	_, err := netlink.LinkByName(interfaceName)
	if err != nil {
		if _, ok := err.(netlink.LinkNotFoundError); ok {
			// Interface doesn't exist, so create it
			err = createWireGuardInterface()
			if err != nil {
				log.Fatalf("Failed to create WireGuard interface: %v", err)
			}
			log.Printf("Created WireGuard interface %s\n", interfaceName)
		} else {
			log.Fatalf("Error checking for WireGuard interface: %v", err)
		}
	} else {
		log.Printf("WireGuard interface %s already exists\n", interfaceName)
		return nil
	}

	// Assign IP address to the interface
	err = assignIPAddress(wgconfig.IpAddress)
	if err != nil {
		log.Fatalf("Failed to assign IP address: %v", err)
	}
	log.Printf("Assigned IP address %s to interface %s\n", wgconfig.IpAddress, interfaceName)

	// Check if the interface already exists
	_, err = wgClient.Device(interfaceName)
	if err != nil {
		return fmt.Errorf("interface %s does not exist", interfaceName)
	}

	// Parse the private key
	key, err := wgtypes.ParseKey(wgconfig.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %v", err)
	}

	// Create a new WireGuard configuration
	config := wgtypes.Config{
		PrivateKey: &key,
		ListenPort: new(int),
	}
	*config.ListenPort = wgconfig.ListenPort

	// Create and configure the WireGuard interface
	err = wgClient.ConfigureDevice(interfaceName, config)
	if err != nil {
		return fmt.Errorf("failed to configure WireGuard device: %v", err)
	}

	// bring up the interface
	link, err := netlink.LinkByName(interfaceName)
	if err != nil {
		return fmt.Errorf("failed to get interface: %v", err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to bring up interface: %v", err)
	}

	log.Printf("WireGuard interface %s created and configured", interfaceName)

	return nil
}

func createWireGuardInterface() error {
	wgLink := &netlink.GenericLink{
		LinkAttrs: netlink.LinkAttrs{Name: interfaceName},
		LinkType:  "wireguard",
	}
	return netlink.LinkAdd(wgLink)
}

func assignIPAddress(ipAddress string) error {
	link, err := netlink.LinkByName(interfaceName)
	if err != nil {
		return fmt.Errorf("failed to get interface: %v", err)
	}

	addr, err := netlink.ParseAddr(ipAddress)
	if err != nil {
		return fmt.Errorf("failed to parse IP address: %v", err)
	}

	return netlink.AddrAdd(link, addr)
}

func ensureWireguardPeers(peers []Peer) error {
	// get the current peers
	device, err := wgClient.Device(interfaceName)
	if err != nil {
		return fmt.Errorf("failed to get device: %v", err)
	}

	// get the peer public keys
	var currentPeers []string
	for _, peer := range device.Peers {
		currentPeers = append(currentPeers, peer.PublicKey.String())
	}

	// remove any peers that are not in the config
	for _, peer := range currentPeers {
		found := false
		for _, configPeer := range peers {
			if peer == configPeer.PublicKey {
				found = true
				break
			}
		}
		if !found {
			err := removePeer(peer)
			if err != nil {
				return fmt.Errorf("failed to remove peer: %v", err)
			}
		}
	}

	// add any peers that are in the config but not in the current peers
	for _, configPeer := range peers {
		found := false
		for _, peer := range currentPeers {
			if configPeer.PublicKey == peer {
				found = true
				break
			}
		}
		if !found {
			err := addPeer(configPeer)
			if err != nil {
				return fmt.Errorf("failed to add peer: %v", err)
			}
		}
	}

	return nil
}

func handlePeer(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		handleAddPeer(w, r)
	case http.MethodDelete:
		handleRemovePeer(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleAddPeer(w http.ResponseWriter, r *http.Request) {
	var peer Peer
	if err := json.NewDecoder(r.Body).Decode(&peer); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err := addPeer(peer)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"status": "Peer added successfully"})
}

func addPeer(peer Peer) error {
	pubKey, err := wgtypes.ParseKey(peer.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %v", err)
	}

	// parse allowed IPs into array of net.IPNet
	var allowedIPs []net.IPNet
	for _, ipStr := range peer.AllowedIPs {
		_, ipNet, err := net.ParseCIDR(ipStr)
		if err != nil {
			return fmt.Errorf("failed to parse allowed IP: %v", err)
		}
		allowedIPs = append(allowedIPs, *ipNet)
	}

	peerConfig := wgtypes.PeerConfig{
		PublicKey:  pubKey,
		AllowedIPs: allowedIPs,
	}

	config := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peerConfig},
	}

	if err := wgClient.ConfigureDevice(interfaceName, config); err != nil {
		return fmt.Errorf("failed to add peer: %v", err)
	}

	log.Printf("Peer %s added successfully", peer.PublicKey)

	return nil
}

func handleRemovePeer(w http.ResponseWriter, r *http.Request) {
	publicKey := r.URL.Query().Get("public_key")
	if publicKey == "" {
		http.Error(w, "Missing public_key query parameter", http.StatusBadRequest)
		return
	}

	err := removePeer(publicKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "Peer removed successfully"})
}

func removePeer(publicKey string) error {
	pubKey, err := wgtypes.ParseKey(publicKey)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %v", err)
	}

	peerConfig := wgtypes.PeerConfig{
		PublicKey: pubKey,
		Remove:    true,
	}

	config := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peerConfig},
	}

	if err := wgClient.ConfigureDevice(interfaceName, config); err != nil {
		return fmt.Errorf("failed to remove peer: %v", err)
	}

	log.Printf("Peer %s removed successfully", publicKey)

	return nil
}

func periodicBandwidthCheck(endpoint string) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		if err := reportPeerBandwidth(endpoint); err != nil {
			log.Printf("Failed to report peer bandwidth: %v", err)
		}
	}
}

func calculatePeerBandwidth() ([]PeerBandwidth, error) {
	device, err := wgClient.Device(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to get device: %v", err)
	}

	peerBandwidths := []PeerBandwidth{}

	for _, peer := range device.Peers {
		// Store initial values
		initialBytesReceived := peer.ReceiveBytes
		initialBytesSent := peer.TransmitBytes

		// Wait for a short period to measure change
		time.Sleep(5 * time.Second)

		// Get updated device info
		updatedDevice, err := wgClient.Device(interfaceName)
		if err != nil {
			return nil, fmt.Errorf("failed to get updated device: %v", err)
		}

		var updatedPeer *wgtypes.Peer
		for _, p := range updatedDevice.Peers {
			if p.PublicKey == peer.PublicKey {
				updatedPeer = &p
				break
			}
		}

		if updatedPeer == nil {
			continue
		}

		// Calculate change in bytes
		bytesInDiff := float64(updatedPeer.ReceiveBytes - initialBytesReceived)
		bytesOutDiff := float64(updatedPeer.TransmitBytes - initialBytesSent)

		// Convert to MB
		bytesInMB := bytesInDiff / (1024 * 1024)
		bytesOutMB := bytesOutDiff / (1024 * 1024)

		peerBandwidths = append(peerBandwidths, PeerBandwidth{
			PublicKey: peer.PublicKey.String(),
			BytesIn:   bytesInMB,
			BytesOut:  bytesOutMB,
		})
	}

	return peerBandwidths, nil
}

func reportPeerBandwidth(apiURL string) error {
	bandwidths, err := calculatePeerBandwidth()
	if err != nil {
		return fmt.Errorf("failed to calculate peer bandwidth: %v", err)
	}

	jsonData, err := json.Marshal(bandwidths)
	if err != nil {
		return fmt.Errorf("failed to marshal bandwidth data: %v", err)
	}

	resp, err := http.Post(apiURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to send bandwidth data: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API returned non-OK status: %s", resp.Status)
	}

	// log.Println("Bandwidth data sent successfully")
	return nil
}
