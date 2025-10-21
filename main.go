package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fosrl/gerbil/logger"
	"github.com/fosrl/gerbil/proxy"
	"github.com/fosrl/gerbil/relay"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var (
	interfaceName string
	listenAddr    string
	mtuInt        int
	lastReadings  = make(map[string]PeerReading)
	mu            sync.Mutex
	wgMu          sync.Mutex // Protects WireGuard operations
	notifyURL     string
	proxyRelay    *relay.UDPProxyServer
	proxySNI      *proxy.SNIProxy
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

type PeerReading struct {
	BytesReceived    int64
	BytesTransmitted int64
	LastChecked      time.Time
}

var (
	wgClient *wgctrl.Client
)

// Add this new type at the top with other type definitions
type ClientEndpoint struct {
	OlmID     string `json:"olmId"`
	NewtID    string `json:"newtId"`
	IP        string `json:"ip"`
	Port      int    `json:"port"`
	Timestamp int64  `json:"timestamp"`
}

type HolePunchMessage struct {
	OlmID  string `json:"olmId"`
	NewtID string `json:"newtId"`
}

type ProxyMappingUpdate struct {
	OldDestination relay.PeerDestination `json:"oldDestination"`
	NewDestination relay.PeerDestination `json:"newDestination"`
}

type UpdateDestinationsRequest struct {
	SourceIP     string                  `json:"sourceIp"`
	SourcePort   int                     `json:"sourcePort"`
	Destinations []relay.PeerDestination `json:"destinations"`
}

func parseLogLevel(level string) logger.LogLevel {
	switch strings.ToUpper(level) {
	case "DEBUG":
		return logger.DEBUG
	case "INFO":
		return logger.INFO
	case "WARN":
		return logger.WARN
	case "ERROR":
		return logger.ERROR
	case "FATAL":
		return logger.FATAL
	default:
		return logger.INFO // default to INFO if invalid level provided
	}
}

func main() {
	var (
		err                  error
		wgconfig             WgConfig
		configFile           string
		remoteConfigURL      string
		generateAndSaveKeyTo string
		reachableAt          string
		logLevel             string
		mtu                  string
		sniProxyPort         int
		localProxyAddr       string
		localProxyPort       int
		localOverridesStr    string
		trustedUpstreamsStr  string
		proxyProtocol        bool
	)

	interfaceName = os.Getenv("INTERFACE")
	configFile = os.Getenv("CONFIG")
	remoteConfigURL = os.Getenv("REMOTE_CONFIG")
	listenAddr = os.Getenv("LISTEN")
	generateAndSaveKeyTo = os.Getenv("GENERATE_AND_SAVE_KEY_TO")
	reachableAt = os.Getenv("REACHABLE_AT")
	logLevel = os.Getenv("LOG_LEVEL")
	mtu = os.Getenv("MTU")
	notifyURL = os.Getenv("NOTIFY_URL")

	sniProxyPortStr := os.Getenv("SNI_PORT")
	localProxyAddr = os.Getenv("LOCAL_PROXY")
	localProxyPortStr := os.Getenv("LOCAL_PROXY_PORT")
	localOverridesStr = os.Getenv("LOCAL_OVERRIDES")
	trustedUpstreamsStr = os.Getenv("TRUSTED_UPSTREAMS")
	proxyProtocolStr := os.Getenv("PROXY_PROTOCOL")

	if interfaceName == "" {
		flag.StringVar(&interfaceName, "interface", "wg0", "Name of the WireGuard interface")
	}
	if configFile == "" {
		flag.StringVar(&configFile, "config", "", "Path to local configuration file")
	}
	if remoteConfigURL == "" {
		flag.StringVar(&remoteConfigURL, "remoteConfig", "", "URL of the Pangolin server")
	}
	if listenAddr == "" {
		flag.StringVar(&listenAddr, "listen", "", "DEPRECATED (overridden by reachableAt): Address to listen on")
	}
	// DEPRECATED AND UNSED: reportBandwidthTo
	// allow reportBandwidthTo to be passed but dont do anything with it just thow it away
	reportBandwidthTo := ""
	flag.StringVar(&reportBandwidthTo, "reportBandwidthTo", "", "DEPRECATED: Use remoteConfig instead")

	if generateAndSaveKeyTo == "" {
		flag.StringVar(&generateAndSaveKeyTo, "generateAndSaveKeyTo", "", "Path to save generated private key")
	}

	if reachableAt == "" {
		flag.StringVar(&reachableAt, "reachableAt", "", "Endpoint of the http server to tell remote config about")
	}

	if logLevel == "" {
		flag.StringVar(&logLevel, "log-level", "INFO", "Log level (DEBUG, INFO, WARN, ERROR, FATAL)")
	}
	if mtu == "" {
		flag.StringVar(&mtu, "mtu", "1280", "MTU of the WireGuard interface")
	}
	if notifyURL == "" {
		flag.StringVar(&notifyURL, "notify", "", "URL to notify on peer changes")
	}

	if sniProxyPortStr != "" {
		if port, err := strconv.Atoi(sniProxyPortStr); err == nil {
			sniProxyPort = port
		}
	}
	if sniProxyPortStr == "" {
		flag.IntVar(&sniProxyPort, "sni-port", 8443, "Port to listen on")
	}

	if localProxyAddr == "" {
		flag.StringVar(&localProxyAddr, "local-proxy", "localhost", "Local proxy address")
	}

	if localProxyPortStr != "" {
		if port, err := strconv.Atoi(localProxyPortStr); err == nil {
			localProxyPort = port
		}
	}
	if localProxyPortStr == "" {
		flag.IntVar(&localProxyPort, "local-proxy-port", 443, "Local proxy port")
	}
	if localOverridesStr != "" {
		flag.StringVar(&localOverridesStr, "local-overrides", "", "Comma-separated list of local overrides for SNI proxy")
	}
	if trustedUpstreamsStr == "" {
		flag.StringVar(&trustedUpstreamsStr, "trusted-upstreams", "", "Comma-separated list of trusted upstream proxy domain names/IPs that can send PROXY protocol")
	}

	if proxyProtocolStr != "" {
		proxyProtocol = strings.ToLower(proxyProtocolStr) == "true"
	}
	if proxyProtocolStr == "" {
		flag.BoolVar(&proxyProtocol, "proxy-protocol", true, "Enable PROXY protocol v1 for preserving client IP")
	}

	flag.Parse()

	logger.Init()
	logger.GetLogger().SetLevel(parseLogLevel(logLevel))

	// try to parse as http://host:port and set the listenAddr to the :port from this reachableAt.
	if reachableAt != "" && listenAddr == "" {
		if strings.HasPrefix(reachableAt, "http://") || strings.HasPrefix(reachableAt, "https://") {
			parts := strings.Split(reachableAt, ":")
			if len(parts) == 3 {
				port := parts[2]
				if strings.Contains(port, "/") {
					port = strings.Split(port, "/")[0]
				}
				listenAddr = ":" + port
			}
		}
	} else if listenAddr == "" {
		listenAddr = ":3003"
	}

	mtuInt, err = strconv.Atoi(mtu)
	if err != nil {
		logger.Fatal("Failed to parse MTU: %v", err)
	}

	// are they missing either the config file or the remote config URL?
	if configFile == "" && remoteConfigURL == "" {
		logger.Fatal("You must provide either a config file or a remote config URL")
	}

	// do they have both the config file and the remote config URL?
	if configFile != "" && remoteConfigURL != "" {
		logger.Fatal("You must provide either a config file or a remote config URL, not both")
	}

	// clean up the reomte config URL for backwards compatibility
	remoteConfigURL = strings.TrimSuffix(remoteConfigURL, "/gerbil/get-config")
	remoteConfigURL = strings.TrimSuffix(remoteConfigURL, "/")

	var key wgtypes.Key
	// if generateAndSaveKeyTo is provided, generate a private key and save it to the file. if the file already exists, load the key from the file
	if generateAndSaveKeyTo != "" {
		if _, err := os.Stat(generateAndSaveKeyTo); os.IsNotExist(err) {
			// generate a new private key
			key, err = wgtypes.GeneratePrivateKey()
			if err != nil {
				logger.Fatal("Failed to generate private key: %v", err)
			}
			// save the key to the file
			err = os.WriteFile(generateAndSaveKeyTo, []byte(key.String()), 0644)
			if err != nil {
				logger.Fatal("Failed to save private key: %v", err)
			}
		} else {
			keyData, err := os.ReadFile(generateAndSaveKeyTo)
			if err != nil {
				logger.Fatal("Failed to read private key: %v", err)
			}
			key, err = wgtypes.ParseKey(string(keyData))
			if err != nil {
				logger.Fatal("Failed to parse private key: %v", err)
			}
		}
	} else {
		// if no generateAndSaveKeyTo is provided, ensure that the private key is provided
		if wgconfig.PrivateKey == "" {
			// generate a new one
			key, err = wgtypes.GeneratePrivateKey()
			if err != nil {
				logger.Fatal("Failed to generate private key: %v", err)
			}
		}
	}

	// Load configuration based on provided argument
	if configFile != "" {
		wgconfig, err = loadConfig(configFile)
		if err != nil {
			logger.Fatal("Failed to load configuration: %v", err)
		}
		if wgconfig.PrivateKey == "" {
			wgconfig.PrivateKey = key.String()
		}
	} else {
		// loop until we get the config
		for wgconfig.PrivateKey == "" {
			logger.Info("Fetching remote config from %s", remoteConfigURL+"/gerbil/get-config")
			wgconfig, err = loadRemoteConfig(remoteConfigURL+"/gerbil/get-config", key, reachableAt)
			if err != nil {
				logger.Error("Failed to load configuration: %v", err)
				time.Sleep(5 * time.Second)
				continue
			}
			wgconfig.PrivateKey = key.String()
		}
	}

	wgClient, err = wgctrl.New()
	if err != nil {
		logger.Fatal("Failed to create WireGuard client: %v", err)
	}
	defer wgClient.Close()

	// Ensure the WireGuard interface exists and is configured
	if err := ensureWireguardInterface(wgconfig); err != nil {
		logger.Fatal("Failed to ensure WireGuard interface: %v", err)
	}

	// Ensure the WireGuard peers exist
	ensureWireguardPeers(wgconfig.Peers)

	go periodicBandwidthCheck(remoteConfigURL + "/gerbil/receive-bandwidth")

	// Start the UDP proxy server
	proxyRelay = relay.NewUDPProxyServer(":21820", remoteConfigURL, key, reachableAt)
	err = proxyRelay.Start()
	if err != nil {
		logger.Fatal("Failed to start UDP proxy server: %v", err)
	}
	defer proxyRelay.Stop()

	// TODO: WE SHOULD PULL THIS OUT OF THE CONFIG OR SOMETHING
	// 		 SO YOU DON'T NEED TO SET THIS SEPARATELY
	// Parse local overrides
	var localOverrides []string
	if localOverridesStr != "" {
		localOverrides = strings.Split(localOverridesStr, ",")
		for i, domain := range localOverrides {
			localOverrides[i] = strings.TrimSpace(domain)
		}
		logger.Info("Local overrides configured: %v", localOverrides)
	}

	var trustedUpstreams []string
	if trustedUpstreamsStr != "" {
		trustedUpstreams = strings.Split(trustedUpstreamsStr, ",")
		for i, upstream := range trustedUpstreams {
			trustedUpstreams[i] = strings.TrimSpace(upstream)
		}
		logger.Info("Trusted upstreams configured: %v", trustedUpstreams)
	}

	proxySNI, err = proxy.NewSNIProxy(sniProxyPort, remoteConfigURL, key.PublicKey().String(), localProxyAddr, localProxyPort, localOverrides, proxyProtocol, trustedUpstreams)
	if err != nil {
		logger.Fatal("Failed to create proxy: %v", err)
	}

	if err := proxySNI.Start(); err != nil {
		logger.Fatal("Failed to start proxy: %v", err)
	}

	// Set up HTTP server
	http.HandleFunc("/peer", handlePeer)
	http.HandleFunc("/update-proxy-mapping", handleUpdateProxyMapping)
	http.HandleFunc("/update-destinations", handleUpdateDestinations)
	http.HandleFunc("/update-local-snis", handleUpdateLocalSNIs)
	logger.Info("Starting HTTP server on %s", listenAddr)

	// Run HTTP server in a goroutine
	go func() {
		if err := http.ListenAndServe(listenAddr, nil); err != nil {
			logger.Error("HTTP server failed: %v", err)
		}
	}()

	// Keep the main goroutine running
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	logger.Info("Shutting down servers...")
}

func loadRemoteConfig(url string, key wgtypes.Key, reachableAt string) (WgConfig, error) {
	var body *bytes.Buffer
	if reachableAt == "" {
		body = bytes.NewBuffer([]byte(fmt.Sprintf(`{"publicKey": "%s"}`, key.PublicKey().String())))
	} else {
		body = bytes.NewBuffer([]byte(fmt.Sprintf(`{"publicKey": "%s", "reachableAt": "%s"}`, key.PublicKey().String(), reachableAt)))
	}
	resp, err := http.Post(url, "application/json", body)
	if err != nil {
		// print the error
		logger.Error("Error fetching remote config %s: %v", url, err)
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
		logger.Error("Error opening file %s: %v", filename, err)
		return WgConfig{}, err
	}
	defer file.Close()

	// Read the file contents
	byteValue, err := io.ReadAll(file)
	if err != nil {
		logger.Error("Error reading file %s: %v", filename, err)
		return WgConfig{}, err
	}

	// Create a variable of the appropriate type to hold the unmarshaled data
	var wgconfig WgConfig

	// Unmarshal the JSON data into the struct
	err = json.Unmarshal(byteValue, &wgconfig)
	if err != nil {
		logger.Error("Error unmarshaling JSON data: %v", err)
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
				logger.Fatal("Failed to create WireGuard interface: %v", err)
			}
			logger.Info("Created WireGuard interface %s\n", interfaceName)
		} else {
			logger.Fatal("Error checking for WireGuard interface: %v", err)
		}
	} else {
		logger.Info("WireGuard interface %s already exists\n", interfaceName)
		return nil
	}

	// Assign IP address to the interface
	err = assignIPAddress(wgconfig.IpAddress)
	if err != nil {
		logger.Fatal("Failed to assign IP address: %v", err)
	}
	logger.Info("Assigned IP address %s to interface %s\n", wgconfig.IpAddress, interfaceName)

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

	if err := netlink.LinkSetMTU(link, mtuInt); err != nil {
		return fmt.Errorf("failed to set MTU: %v", err)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to bring up interface: %v", err)
	}

	if err := ensureMSSClamping(); err != nil {
		logger.Warn("Failed to ensure MSS clamping: %v", err)
	}

	logger.Info("WireGuard interface %s created and configured", interfaceName)

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
	wgMu.Lock()
	defer wgMu.Unlock()

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
			// Note: We need to call the internal removal logic without re-acquiring the lock
			if err := removePeerInternal(peer); err != nil {
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
			// Note: We need to call the internal addition logic without re-acquiring the lock
			if err := addPeerInternal(configPeer); err != nil {
				return fmt.Errorf("failed to add peer: %v", err)
			}
		}
	}

	return nil
}

func ensureMSSClamping() error {
	// Calculate MSS value (MTU - 40 for IPv4 header (20) and TCP header (20))
	mssValue := mtuInt - 40

	// Rules to be managed - just the chains, we'll construct the full command separately
	chains := []string{"INPUT", "OUTPUT", "FORWARD"}

	// First, try to delete any existing rules
	for _, chain := range chains {
		deleteCmd := exec.Command("/usr/sbin/iptables",
			"-t", "mangle",
			"-D", chain,
			"-p", "tcp",
			"--tcp-flags", "SYN,RST", "SYN",
			"-j", "TCPMSS",
			"--set-mss", fmt.Sprintf("%d", mssValue))

		logger.Info("Attempting to delete existing MSS clamping rule for chain %s", chain)

		// Try deletion multiple times to handle multiple existing rules
		for i := 0; i < 3; i++ {
			out, err := deleteCmd.CombinedOutput()
			if err != nil {
				// Convert exit status 1 to string for better logging
				if exitErr, ok := err.(*exec.ExitError); ok {
					logger.Debug("Deletion stopped for chain %s: %v (output: %s)",
						chain, exitErr.String(), string(out))
				}
				break // No more rules to delete
			}
			logger.Info("Deleted MSS clamping rule for chain %s (attempt %d)", chain, i+1)
		}
	}

	// Then add the new rules
	var errors []error
	for _, chain := range chains {
		addCmd := exec.Command("/usr/sbin/iptables",
			"-t", "mangle",
			"-A", chain,
			"-p", "tcp",
			"--tcp-flags", "SYN,RST", "SYN",
			"-j", "TCPMSS",
			"--set-mss", fmt.Sprintf("%d", mssValue))

		logger.Info("Adding MSS clamping rule for chain %s", chain)

		if out, err := addCmd.CombinedOutput(); err != nil {
			errMsg := fmt.Sprintf("Failed to add MSS clamping rule for chain %s: %v (output: %s)",
				chain, err, string(out))
			logger.Error(errMsg)
			errors = append(errors, fmt.Errorf("%s", errMsg))
			continue
		}

		// Verify the rule was added
		checkCmd := exec.Command("/usr/sbin/iptables",
			"-t", "mangle",
			"-C", chain,
			"-p", "tcp",
			"--tcp-flags", "SYN,RST", "SYN",
			"-j", "TCPMSS",
			"--set-mss", fmt.Sprintf("%d", mssValue))

		if out, err := checkCmd.CombinedOutput(); err != nil {
			errMsg := fmt.Sprintf("Rule verification failed for chain %s: %v (output: %s)",
				chain, err, string(out))
			logger.Error(errMsg)
			errors = append(errors, fmt.Errorf("%s", errMsg))
			continue
		}

		logger.Info("Successfully added and verified MSS clamping rule for chain %s", chain)
	}

	// If we encountered any errors, return them combined
	if len(errors) > 0 {
		var errMsgs []string
		for _, err := range errors {
			errMsgs = append(errMsgs, err.Error())
		}
		return fmt.Errorf("MSS clamping setup encountered errors:\n%s",
			strings.Join(errMsgs, "\n"))
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

	// Notify if notifyURL is set
	go notifyPeerChange("add", peer.PublicKey)

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"status": "Peer added successfully"})
}

func addPeer(peer Peer) error {
	wgMu.Lock()
	defer wgMu.Unlock()
	return addPeerInternal(peer)
}

func addPeerInternal(peer Peer) error {
	pubKey, err := wgtypes.ParseKey(peer.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %v", err)
	}

	// parse allowed IPs into array of net.IPNet
	var allowedIPs []net.IPNet
	var wgIPs []string
	for _, ipStr := range peer.AllowedIPs {
		_, ipNet, err := net.ParseCIDR(ipStr)
		if err != nil {
			return fmt.Errorf("failed to parse allowed IP: %v", err)
		}
		allowedIPs = append(allowedIPs, *ipNet)
		// Extract the IP address from the CIDR for relay cleanup
		wgIPs = append(wgIPs, ipNet.IP.String())
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

	// Clear relay connections for the peer's WireGuard IPs
	if proxyRelay != nil {
		for _, wgIP := range wgIPs {
			proxyRelay.OnPeerAdded(wgIP)
		}
	}

	logger.Info("Peer %s added successfully", peer.PublicKey)

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

	// Notify if notifyURL is set
	go notifyPeerChange("remove", publicKey)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "Peer removed successfully"})
}

func removePeer(publicKey string) error {
	wgMu.Lock()
	defer wgMu.Unlock()
	return removePeerInternal(publicKey)
}

func removePeerInternal(publicKey string) error {
	pubKey, err := wgtypes.ParseKey(publicKey)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %v", err)
	}

	// Get current peer info before removing to clear relay connections
	var wgIPs []string
	if proxyRelay != nil {
		device, err := wgClient.Device(interfaceName)
		if err == nil {
			for _, peer := range device.Peers {
				if peer.PublicKey.String() == publicKey {
					// Extract WireGuard IPs from this peer's allowed IPs
					for _, allowedIP := range peer.AllowedIPs {
						wgIPs = append(wgIPs, allowedIP.IP.String())
					}
					break
				}
			}
		}
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

	// Clear relay connections for the peer's WireGuard IPs
	if proxyRelay != nil {
		for _, wgIP := range wgIPs {
			proxyRelay.OnPeerRemoved(wgIP)
		}
	}

	logger.Info("Peer %s removed successfully", publicKey)

	return nil
}

func handleUpdateProxyMapping(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		logger.Error("Invalid method: %s", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var update ProxyMappingUpdate
	if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
		logger.Error("Failed to decode request body: %v", err)
		http.Error(w, fmt.Sprintf("Failed to decode request body: %v", err), http.StatusBadRequest)
		return
	}

	// Validate the update request
	if update.OldDestination.DestinationIP == "" || update.NewDestination.DestinationIP == "" {
		logger.Error("Both old and new destination IP addresses are required")
		http.Error(w, "Both old and new destination IP addresses are required", http.StatusBadRequest)
		return
	}

	if update.OldDestination.DestinationPort <= 0 || update.NewDestination.DestinationPort <= 0 {
		logger.Error("Both old and new destination ports must be positive integers")
		http.Error(w, "Both old and new destination ports must be positive integers", http.StatusBadRequest)
		return
	}

	// Update the proxy mappings in the relay server
	if proxyRelay == nil {
		logger.Error("Proxy server is not available")
		http.Error(w, "Proxy server is not available", http.StatusInternalServerError)
		return
	}

	updatedCount := proxyRelay.UpdateDestinationInMappings(update.OldDestination, update.NewDestination)

	logger.Info("Updated %d proxy mappings: %s:%d -> %s:%d",
		updatedCount,
		update.OldDestination.DestinationIP, update.OldDestination.DestinationPort,
		update.NewDestination.DestinationIP, update.NewDestination.DestinationPort)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":         "Proxy mappings updated successfully",
		"updatedCount":   updatedCount,
		"oldDestination": update.OldDestination,
		"newDestination": update.NewDestination,
	})
}

func handleUpdateDestinations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		logger.Error("Invalid method: %s", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var request UpdateDestinationsRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		logger.Error("Failed to decode request body: %v", err)
		http.Error(w, fmt.Sprintf("Failed to decode request body: %v", err), http.StatusBadRequest)
		return
	}

	// Validate the request
	if request.SourceIP == "" {
		logger.Error("Source IP address is required")
		http.Error(w, "Source IP address is required", http.StatusBadRequest)
		return
	}

	if request.SourcePort <= 0 {
		logger.Error("Source port must be a positive integer")
		http.Error(w, "Source port must be a positive integer", http.StatusBadRequest)
		return
	}

	if len(request.Destinations) == 0 {
		logger.Error("At least one destination is required")
		http.Error(w, "At least one destination is required", http.StatusBadRequest)
		return
	}

	// Validate each destination
	for i, dest := range request.Destinations {
		if dest.DestinationIP == "" {
			logger.Error("Destination IP is required for destination %d", i)
			http.Error(w, fmt.Sprintf("Destination IP is required for destination %d", i), http.StatusBadRequest)
			return
		}
		if dest.DestinationPort <= 0 {
			logger.Error("Destination port must be a positive integer for destination %d", i)
			http.Error(w, fmt.Sprintf("Destination port must be a positive integer for destination %d", i), http.StatusBadRequest)
			return
		}
	}

	// Update the proxy mappings in the relay server
	if proxyRelay == nil {
		logger.Error("Proxy server is not available")
		http.Error(w, "Proxy server is not available", http.StatusInternalServerError)
		return
	}

	proxyRelay.UpdateProxyMapping(request.SourceIP, request.SourcePort, request.Destinations)

	logger.Info("Updated proxy mapping for %s:%d with %d destinations",
		request.SourceIP, request.SourcePort, len(request.Destinations))

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":           "Destinations updated successfully",
		"sourceIP":         request.SourceIP,
		"sourcePort":       request.SourcePort,
		"destinationCount": len(request.Destinations),
		"destinations":     request.Destinations,
	})
}

// UpdateLocalSNIsRequest represents the JSON payload for updating local SNIs
type UpdateLocalSNIsRequest struct {
	FullDomains []string `json:"fullDomains"`
}

func handleUpdateLocalSNIs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		logger.Error("Invalid method: %s", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req UpdateLocalSNIsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	proxySNI.UpdateLocalSNIs(req.FullDomains)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "Local SNIs updated successfully",
	})
}

func periodicBandwidthCheck(endpoint string) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		if err := reportPeerBandwidth(endpoint); err != nil {
			logger.Info("Failed to report peer bandwidth: %v", err)
		}
	}
}

func calculatePeerBandwidth() ([]PeerBandwidth, error) {
	wgMu.Lock()
	device, err := wgClient.Device(interfaceName)
	wgMu.Unlock()

	if err != nil {
		return nil, fmt.Errorf("failed to get device: %v", err)
	}

	peerBandwidths := []PeerBandwidth{}
	now := time.Now()

	mu.Lock()
	defer mu.Unlock()

	for _, peer := range device.Peers {
		publicKey := peer.PublicKey.String()
		currentReading := PeerReading{
			BytesReceived:    peer.ReceiveBytes,
			BytesTransmitted: peer.TransmitBytes,
			LastChecked:      now,
		}

		var bytesInDiff, bytesOutDiff float64
		lastReading, exists := lastReadings[publicKey]

		if exists {
			timeDiff := currentReading.LastChecked.Sub(lastReading.LastChecked).Seconds()
			if timeDiff > 0 {
				// Calculate bytes transferred since last reading
				bytesInDiff = float64(currentReading.BytesReceived - lastReading.BytesReceived)
				bytesOutDiff = float64(currentReading.BytesTransmitted - lastReading.BytesTransmitted)

				// Handle counter wraparound (if the counter resets or overflows)
				if bytesInDiff < 0 {
					bytesInDiff = float64(currentReading.BytesReceived)
				}
				if bytesOutDiff < 0 {
					bytesOutDiff = float64(currentReading.BytesTransmitted)
				}

				// Convert to MB
				bytesInMB := bytesInDiff / (1024 * 1024)
				bytesOutMB := bytesOutDiff / (1024 * 1024)

				peerBandwidths = append(peerBandwidths, PeerBandwidth{
					PublicKey: publicKey,
					BytesIn:   bytesInMB,
					BytesOut:  bytesOutMB,
				})
			} else {
				// If readings are too close together or time hasn't passed, report 0
				peerBandwidths = append(peerBandwidths, PeerBandwidth{
					PublicKey: publicKey,
					BytesIn:   0,
					BytesOut:  0,
				})
			}
		} else {
			// For first reading of a peer, report 0 to establish baseline
			peerBandwidths = append(peerBandwidths, PeerBandwidth{
				PublicKey: publicKey,
				BytesIn:   0,
				BytesOut:  0,
			})
		}

		// Update the last reading
		lastReadings[publicKey] = currentReading
	}

	// Clean up old peers
	for publicKey := range lastReadings {
		found := false
		for _, peer := range device.Peers {
			if peer.PublicKey.String() == publicKey {
				found = true
				break
			}
		}
		if !found {
			delete(lastReadings, publicKey)
		}
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

	return nil
}

// notifyPeerChange sends a POST request to notifyURL with the action and public key.
func notifyPeerChange(action, publicKey string) {
	if notifyURL == "" {
		return
	}
	payload := map[string]string{
		"action":    action,
		"publicKey": publicKey,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		logger.Warn("Failed to marshal notify payload: %v", err)
		return
	}
	resp, err := http.Post(notifyURL, "application/json", bytes.NewBuffer(data))
	if err != nil {
		logger.Warn("Failed to notify peer change: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		logger.Warn("Notify server returned non-OK: %s", resp.Status)
	}
}
