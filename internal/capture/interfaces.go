// Package capture provides primitives for discovering network interfaces
// and capturing packets using libpcap via the gopacket library.
package capture

import "github.com/google/gopacket/pcap"

// Interface holds the metadata we care about for a network interface.
type Interface struct {
	Name        string
	Description string
	// Addresses contains the string representation of every IP address
	// assigned to this interface (both IPv4 and IPv6).
	Addresses []string
}

// findAllDevs is the live implementation of the libpcap device discovery
// call. It is a package-level variable so tests can replace it with a stub
// without needing an OS-level pcap environment.
var findAllDevs = pcap.FindAllDevs

// FindInterfaces returns all network interfaces visible to libpcap on the
// current machine. It converts the raw pcap types into the lighter-weight
// Interface struct so the rest of the application never imports gopacket
// directly.
func FindInterfaces() ([]Interface, error) {
	devices, err := findAllDevs()
	if err != nil {
		return nil, err
	}

	ifaces := make([]Interface, 0, len(devices))
	for _, d := range devices {
		addrs := make([]string, 0, len(d.Addresses))
		for _, a := range d.Addresses {
			if a.IP != nil {
				addrs = append(addrs, a.IP.String())
			}
		}
		ifaces = append(ifaces, Interface{
			Name:        d.Name,
			Description: d.Description,
			Addresses:   addrs,
		})
	}
	return ifaces, nil
}
