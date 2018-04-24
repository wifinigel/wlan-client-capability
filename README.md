# wlan-client-capability
Python script to check wireless (802.11) capabilities based on authentication frame contents

This script uses scapy to listen for an authenciation frame from a client. It will then capture that frame and analyze it to create a report based on the capabilities reported by the client device. It can also be used to analyze the contents of a pcap file that contains a single authentication frame.

Note that this is work in progress and is not production ready.

