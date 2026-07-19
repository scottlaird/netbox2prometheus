package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"

	httptransport "github.com/go-openapi/runtime/client"
	"github.com/netbox-community/go-netbox/v3/netbox/client"
	"github.com/scottlaird/netboxlib/netbox"
	"inet.af/netaddr"
)

type DHCPNetwork struct {
	Protocol int          `json:"-"`
	Prefix   netip.Prefix `json:"subnet"`
	Ranges   []DHCPRange  `json:"pools"`
	Hosts    []*DHCPHost  `json:"reservations"`
	Router   netip.Addr   `json:"-"`
	Options  []DHCPOption `json:"option-data,omitempty"`
	ID       int          `json:"id,omitempty"`
}

type DHCPRange struct {
	Start, Stop netip.Addr `json:"-"`
	Pool        string     `json:"pool"`
	ClientClass string     `json:"client-class,omitempty"`
}

type DHCPHost struct {
	Name string     `json:"hostname"`
	Addr netip.Addr `json:"ip-address"`
	MAC  string     `json:"hw-address"`
}

type DHCPOption struct {
	Name string `json:"name"`
	Data string `json:"data"`
}

var (
	config = flag.String("config", "", "Path of a config file, with a .yaml, .json, or .cue extension")
)

func main() {
	flag.Parse()

	// Load config file
	var err error
	file := *config
	if file == "" {
		file, err = FindConfig("netbox2kea")
		if err != nil {
			log.Fatal(err)
		}
	}
	cfg, err := ParseConfig(file)
	if err != nil {
		log.Fatalf("Failed to parse config: %v", err)
	}

	dhcpNetworks := make(map[netip.Prefix]*DHCPNetwork)

	transport := httptransport.New(cfg.Netbox.Host, client.DefaultBasePath, []string{"https"})
	transport.DefaultAuthentication = httptransport.APIKeyAuth("Authorization", "header", "Token "+cfg.Netbox.Token)
	c := client.New(transport, nil)

	// Fetch address, range, and prefix data from Netbox
	prefixes, err := netbox.ListIPPrefixes(c)
	if err != nil {
		panic(err)
	}

	addrs, err := netbox.ListIPAddrs(c)
	if err != nil {
		panic(err)
	}

	ranges, err := netbox.ListIPRanges(c)
	if err != nil {
		panic(err)
	}

	slices.SortFunc(prefixes, func(a, b *netbox.IPPrefix) int {
		return strings.Compare(a.Prefix.String(), b.Prefix.String())
	})

	networkID:=1;
	for _, prefix := range prefixes {
		if prefix.Tags[cfg.PrefixTag] {
			net := &DHCPNetwork{
				Prefix: prefix.Prefix,
				Ranges: []DHCPRange{},
				Hosts:  []*DHCPHost{},
				ID: networkID,
			}
			networkID++
			
			if prefix.Prefix.Addr().Is4() {
				net.Protocol = 4
			} else if prefix.Prefix.Addr().Is6() {
				net.Protocol = 6
			}
			dhcpNetworks[prefix.Prefix] = net

			if net.Protocol == 4 {
				// Find the highest IP in this netblock, .254 in a /24, etc.
				pf := netaddr.MustParseIPPrefix(prefix.Prefix.String())
				router := pf.Range().To().Prior().String()
				net.Router = netip.MustParseAddr(router)
			}

			if net.Router.IsValid() {
				net.Options = append(net.Options, DHCPOption{Name: "routers", Data: net.Router.String()})
			}
		}
	}

	haclass := 0
	for _, r := range ranges {
		haclass++
		if haclass > 2 {
			haclass = 1
		}
		if r.Tags[cfg.RangeTag] {
			rr := DHCPRange{
				Start: r.StartAddress.Addr(),
				Stop:  r.EndAddress.Addr(),
			}
			rr.Pool = rr.Start.String() + " - " + rr.Stop.String()
			rr.ClientClass = fmt.Sprintf("HA_server%d", haclass)

			found := false
			for prefix, net := range dhcpNetworks {
				if prefix.Contains(rr.Start) {
					net.Ranges = append(net.Ranges, rr)
					found = true
				}
			}
			if found == false {
				fmt.Printf("Could not match range %s-%s to network!\n", rr.Start.String(), rr.Stop.String())
			}
		}
	}

	for _, addr := range addrs {
		if mac, ok := addr.CustomFields[cfg.MacCustomField]; ok {
			if mac.IsValid() {
				val, ok := mac.Interface().(string)

				if ok {
					host := &DHCPHost{
						Name: addr.DNSName,
						Addr: addr.Address.Addr(),
						MAC:  val,
					}

					found := false
					for prefix, net := range dhcpNetworks {
						if prefix.Contains(host.Addr) {
							net.Hosts = append(net.Hosts, host)
							found = true
						}
					}
					if found == false {
						fmt.Printf("Could not match host %s to network!\n", host.Addr.String())
					}
				}
			}
		}
	}

	for prefix, net := range dhcpNetworks {
		if len(net.Ranges) == 0 {
			delete(dhcpNetworks, prefix)
		}
	}

	nets := make(map[int][]*DHCPNetwork)

	// Needed so that JSON encoding returns [] instead of null
	// when no nets are found.
	nets[4] = []*DHCPNetwork{}
	nets[6] = []*DHCPNetwork{}

	for _, net := range dhcpNetworks {
		nets[net.Protocol] = append(nets[net.Protocol], net)
	}

	err = WriteNetwork(filepath.Join(cfg.KeaDirectory, "subnet4.json"), nets[4])
	if err != nil {
		panic(err)
	}
	err = WriteNetwork(filepath.Join(cfg.KeaDirectory, "subnet6.json"), nets[6])
	if err != nil {
		panic(err)
	}
}

func WriteNetwork(filename string, nets []*DHCPNetwork) error {
	out, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer out.Close()

	b, err := json.MarshalIndent(nets, "", "  ")
	if err != nil {
		return err
	}

	_, err = out.Write(b)
	return err
}
