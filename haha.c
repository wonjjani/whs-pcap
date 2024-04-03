//// Packet Sniffing Using The PCAP API

// Step 1 : Open live pcap session on NIC with name eth3
handle = pcap_open_live("eth3", BUFSIZ, 1, 1000, errbuf); // Initialize a raw socket, set the network device into promiscuous moe

// Step 2 : Compile filter_exp into BPF psuedo-code
pcap_compile(handle, &fp, filter_exp, 0, net); // char filter_exp[] = "ip proto icmp";
pcap_setfilter(handle, &fp);

// Step 3 : Capture packets
pcap_ioop(handle, -1, got_packet, NULL); // Invoke this function for every captured packet

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	printf("Got a packet\n");
}


//// Processing Captured Packet: Ethernet Header

/* Ethernet header */
struct ethheader {
	u_char ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* source host address */
	u_short ether_type;		     /* IP? ARP? RARP? etc */
};

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	struct ethheader *eth = (struct ethheader *)packet;
	if (ntohs(eth->ether_type) == 0x0800) { ... } // IP pcket
	....
}



