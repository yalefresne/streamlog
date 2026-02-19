// listinterfaces prints every network interface that libpcap can see on
// the current machine, along with its assigned IP addresses.
//
// On Linux this command typically requires root or the CAP_NET_RAW
// capability:
//
//	sudo ./listinterfaces
package main

import (
	"fmt"
	"log"
	"strings"

	"github.com/yalefresne/streamlog/internal/capture"
)

func main() {
	ifaces, err := capture.FindInterfaces()
	if err != nil {
		log.Fatalf("error listing interfaces: %v", err)
	}

	if len(ifaces) == 0 {
		fmt.Println("no interfaces found (are you running with sufficient privileges?)")
		return
	}

	fmt.Printf("found %d interface(s):\n\n", len(ifaces))
	for _, iface := range ifaces {
		fmt.Printf("  name:        %s\n", iface.Name)
		if iface.Description != "" {
			fmt.Printf("  description: %s\n", iface.Description)
		}
		if len(iface.Addresses) > 0 {
			fmt.Printf("  addresses:   %s\n", strings.Join(iface.Addresses, ", "))
		}
		fmt.Println()
	}
}
