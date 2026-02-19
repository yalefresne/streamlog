package capture

import (
	"net"
	"testing"

	"github.com/google/gopacket/pcap"
)

// TestFindInterfaces_mapsFields verifies that FindInterfaces correctly
// transforms pcap.Interface values into our own Interface structs.
//
// The test stubs findAllDevs so it never performs a real system call —
// this keeps the test fast, hermetic, and runnable without root privileges
// or a live libpcap environment.
func TestFindInterfaces_mapsFields(t *testing.T) {
	// Arrange: replace the live finder with a deterministic stub.
	original := findAllDevs
	defer func() { findAllDevs = original }()

	findAllDevs = func() ([]pcap.Interface, error) {
		return []pcap.Interface{
			{
				Name:        "eth0",
				Description: "Ethernet adapter",
				Addresses: []pcap.InterfaceAddress{
					{IP: net.ParseIP("192.168.1.42")},
					{IP: net.ParseIP("fe80::1")},
				},
			},
		}, nil
	}

	// Act.
	ifaces, err := FindInterfaces()

	// Assert.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ifaces) != 1 {
		t.Fatalf("expected 1 interface, got %d", len(ifaces))
	}

	got := ifaces[0]
	if got.Name != "eth0" {
		t.Errorf("Name: want %q, got %q", "eth0", got.Name)
	}
	if got.Description != "Ethernet adapter" {
		t.Errorf("Description: want %q, got %q", "Ethernet adapter", got.Description)
	}
	if len(got.Addresses) != 2 {
		t.Fatalf("Addresses: want 2 entries, got %d", len(got.Addresses))
	}
	if got.Addresses[0] != "192.168.1.42" {
		t.Errorf("Addresses[0]: want %q, got %q", "192.168.1.42", got.Addresses[0])
	}
	if got.Addresses[1] != "fe80::1" {
		t.Errorf("Addresses[1]: want %q, got %q", "fe80::1", got.Addresses[1])
	}
}

// TestFindInterfaces_empty confirms that an empty device list is handled
// gracefully and returns a non-nil, zero-length slice.
func TestFindInterfaces_empty(t *testing.T) {
	original := findAllDevs
	defer func() { findAllDevs = original }()

	findAllDevs = func() ([]pcap.Interface, error) {
		return []pcap.Interface{}, nil
	}

	ifaces, err := FindInterfaces()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ifaces) != 0 {
		t.Errorf("expected empty slice, got %d elements", len(ifaces))
	}
}

// TestFindInterfaces_nilIP ensures that a nil IP address in the underlying
// pcap.InterfaceAddress slice is handled without panicking or returning
// an error.
func TestFindInterfaces_nilIP(t *testing.T) {
	original := findAllDevs
	defer func() { findAllDevs = original }()
	findAllDevs = func() ([]pcap.Interface, error) {
		return []pcap.Interface{
			{
				Name:        "lo0",
				Description: "Loopback interface",
				Addresses: []pcap.InterfaceAddress{
					{IP: nil},
					{IP: net.ParseIP("127.0.0.1")},
				},
			},
		}, nil
	}
	ifaces, err := FindInterfaces()
	if err != nil {
		t.Fatalf("unexpected error handling nil IP address: %v", err)
	}
	if len(ifaces) != 1 {
		t.Fatalf("expected 1 interface, got %d", len(ifaces))
	}
}
