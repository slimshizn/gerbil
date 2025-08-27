package proxy

import (
	"net"
	"testing"
)

func TestBuildProxyProtocolHeader(t *testing.T) {
	tests := []struct {
		name       string
		clientAddr string
		targetAddr string
		expected   string
	}{
		{
			name:       "IPv4 client and target",
			clientAddr: "192.168.1.100:12345",
			targetAddr: "10.0.0.1:443",
			expected:   "PROXY TCP4 192.168.1.100 10.0.0.1 12345 443\r\n",
		},
		{
			name:       "IPv6 client and target",
			clientAddr: "[2001:db8::1]:12345",
			targetAddr: "[2001:db8::2]:443",
			expected:   "PROXY TCP6 2001:db8::1 2001:db8::2 12345 443\r\n",
		},
		{
			name:       "IPv4 client with IPv6 loopback target",
			clientAddr: "192.168.1.100:12345",
			targetAddr: "[::1]:443",
			expected:   "PROXY TCP4 192.168.1.100 127.0.0.1 12345 443\r\n",
		},
		{
			name:       "IPv4 client with IPv6 target",
			clientAddr: "192.168.1.100:12345",
			targetAddr: "[2001:db8::2]:443",
			expected:   "PROXY TCP4 192.168.1.100 127.0.0.1 12345 443\r\n",
		},
		{
			name:       "IPv6 client with IPv4 target",
			clientAddr: "[2001:db8::1]:12345",
			targetAddr: "10.0.0.1:443",
			expected:   "PROXY TCP6 2001:db8::1 ::ffff:10.0.0.1 12345 443\r\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientTCP, err := net.ResolveTCPAddr("tcp", tt.clientAddr)
			if err != nil {
				t.Fatalf("Failed to resolve client address: %v", err)
			}

			targetTCP, err := net.ResolveTCPAddr("tcp", tt.targetAddr)
			if err != nil {
				t.Fatalf("Failed to resolve target address: %v", err)
			}

			result := buildProxyProtocolHeader(clientTCP, targetTCP)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestBuildProxyProtocolHeaderUnknownType(t *testing.T) {
	// Test with non-TCP address type
	clientAddr := &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 12345}
	targetAddr := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 443}

	result := buildProxyProtocolHeader(clientAddr, targetAddr)
	expected := "PROXY UNKNOWN\r\n"

	if result != expected {
		t.Errorf("Expected %q, got %q", expected, result)
	}
}
