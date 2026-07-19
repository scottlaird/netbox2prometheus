// This defines the configuration format for netbox2prometheus, along with
// validation rules for each field.  See http://cuelang.org for
// documenation.

// This is the template for the actual configuration.
config: {
	// Netbox config settings.
	netbox: {
		host:  string
		token: string
	}

	dns_refresh: *"5m" | string
	dns_server: *"8.8.8.8" | string
	icmp_interval: *"3s" | string
	icmp_timeout: *"500ms" | string
	icmp_count: *6 | int

	domain_name: *"internal.sigkill.org" | string
	prometheus_directory: *"/etc/prometheus" | string
	
	ping_tag_slug:     *"monitoringping_test" | string
	snmp_tag_slug:       *"monitoring:snmp" | string
}
