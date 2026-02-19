// streamlog captures DNS and TLS Client Hello (SNI) packets on enp1s0f0
// using AF_PACKET to avoid libpcap dependency.
package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/afpacket"
	"github.com/gopacket/gopacket/layers"
)

const (
	device    = "enp1s0f0"
	frameSize = 2048
	numBlocks = 128
)

func main() {
	pageSize := os.Getpagesize()
	blockSize := pageSize * numBlocks
	// Ensure we are running on Linux as AF_PACKET is Linux-specific.
	if os.Getenv("GOOS") != "linux" && os.Getenv("GOOS") != "" {
		log.Println("Warning: This program is designed for Linux (AF_PACKET).")
	}

	log.Printf("Starting capture on %s...", device)

	// Create the AF_PACKET handle.
	handle, err := afpacket.NewTPacket(
		afpacket.OptInterface(device),
		afpacket.OptFrameSize(frameSize),
		afpacket.OptBlockSize(blockSize),
		afpacket.OptNumBlocks(numBlocks), // Larger buffer for capture
	)
	if err != nil {
		log.Fatalf("Error creating AF_PACKET handle: %v", err)
	}
	defer handle.Close()

	// Parse packets using gopacket.
	packetSource := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)

	// Channel to signal stop.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	// Use a channel to process packets concurrently if needed, but since
	// packet extraction is fast, we can process in the main loop or spawn
	// goroutines per packet type.
	// The requirement is "concurrently extract and print". We'll use a worker pool model
	// or simple per-packet goroutine (might be too heavy). Let's use a fan-out approach.

	packetChan := packetSource.Packets()

	log.Println("Listening for DNS (53) and TLS (443) packets...")

	for {
		select {
		case <-stop:
			log.Println("Stopping capture...")
			return
		case packet, ok := <-packetChan:
			if !ok {
				return
			}
			// Dispatch processing to a goroutine to handle "concurrently".
			// Note: For high throughput, a worker pool is better, but for this
			// assignment, spawning a goroutine per packet of interest simplifies logic.
			go processPacket(packet)
		}
	}
}

func processPacket(packet gopacket.Packet) {
	// We are looking for DNS (UDP/TCP 53) and TLS (TCP 443).
	// Let's filter first.

	// Check for DNS
	if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
		dns, _ := dnsLayer.(*layers.DNS)
		if dns.QR {
			// Response, maybe we want queries? "extract and print DNS queries"
			// Usually queries are QR=false. But user said "DNS queries".
			// Assuming they want to see what is being queried.
			return
		}
		if len(dns.Questions) > 0 {
			for _, q := range dns.Questions {
				fmt.Printf("[DNS] Query: %s (Type: %s)\n", string(q.Name), q.Type)
			}
		}
		return
	}

	// Check for TLS (TCP 443 usually, but let's check port layer)
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		// Check destination port for Client Hello (target port 443)
		// Or source port if capturing server response (Server Hello).
		// User said "TLS Client Hello (SNI)". This is client -> server.
		// So DstPort should be 443 is common, but could be others.
		// We'll trust the payload parsing.

		// Note: gopacket layers.TLS might not be fully reliable for all TLS traffic
		// or if not enabled by default decoding.
		// We can check if existing payload looks like TLS.

		// If application layer is available
		appLayer := packet.ApplicationLayer()
		if appLayer != nil {
			payload := appLayer.Payload()
			// Basic TLS Client Hello check:
			// Content Type: Handshake (22)
			// Version: 0x0301 (TLS 1.0) or 0x0303 (TLS 1.2) etc.
			// Handshake Type: Client Hello (1)

			if len(payload) > 5 && payload[0] == 22 { // Handshake
				// Skip record header (5 bytes)
				// Handshake header: Type (1 byte), Length (3 bytes)
				if payload[5] == 1 { // Client Hello
					sni := extractSNI(payload)
					if sni != "" {
						fmt.Printf("[TLS] SNI: %s (Src: %s, Dst: %s)\n", sni, packet.NetworkLayer().NetworkFlow().Src(), packet.NetworkLayer().NetworkFlow().Dst())
					}
				}
			}
		}
	}
}

// extractSNI parses the TLS Client Hello payload to find the SNI extension.
func extractSNI(payload []byte) string {
	// This is a simplified parser. Robust one would use cryptobyte or similar.
	// Structure:
	// Record Header (5 bytes)
	// Handshake Header (4 bytes)
	// Client Version (2 bytes)
	// Client Random (32 bytes)
	// Session ID Len (1 byte)
	// Session ID (variable)
	// Cipher Suites Len (2 bytes)
	// Cipher Suites (variable)
	// Compression Methods Len (1 byte)
	// Compression Methods (variable)
	// Extensions Len (2 bytes)
	// Extensions (variable)

	if len(payload) < 43 {
		return ""
	}

	offset := 5 + 4 // Skip Record + Handshake headers
	offset += 2     // Version
	offset += 32    // Random

	if offset >= len(payload) {
		return ""
	}
	sessIDLen := int(payload[offset])
	offset += 1 + sessIDLen

	if offset+2 > len(payload) {
		return ""
	}
	cipherSuitesLen := int(payload[offset])<<8 | int(payload[offset+1])
	offset += 2 + cipherSuitesLen

	if offset+1 > len(payload) {
		return ""
	}
	compMethodsLen := int(payload[offset])
	offset += 1 + compMethodsLen

	if offset+2 > len(payload) {
		return ""
	}
	extensionsLen := int(payload[offset])<<8 | int(payload[offset+1])
	offset += 2

	end := offset + extensionsLen
	if end > len(payload) {
		end = len(payload)
	}

	for offset+4 <= end {
		extType := int(payload[offset])<<8 | int(payload[offset+1])
		extLen := int(payload[offset+2])<<8 | int(payload[offset+3])
		offset += 4

		if extType == 0 { // Server Name Indication
			if offset+extLen > end {
				return ""
			}
			// SNI structure:
			// List Length (2 bytes)
			// Type (1 byte) (0 = host_name)
			// Length (2 bytes)
			// HostName (variable)
			if extLen < 5 {
				return ""
			}
			sniLen := int(payload[offset+3])<<8 | int(payload[offset+4])
			if offset+5+sniLen > end {
				return ""
			}
			return string(payload[offset+5 : offset+5+sniLen])
		}
		offset += extLen
	}

	return ""
}
