// This defines the configuration format for netbox2kea, along with
// validation rules for each field.  See http://cuelang.org for
// documenation.

// This is the template for the actual configuration.
config: {
	// Netbox config settings.
	netbox: {
		host:  string
		token: string
	}

	kea_directory: *"/etc/kea" | string
	
	prefix_tag:     *"subnet:dhcp" | string
	range_tag:       *"subnet:dhcp:range" | string
	mac_custom_field: *"mac_address" | string
}
