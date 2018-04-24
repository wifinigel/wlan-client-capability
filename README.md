# wlan-client-capability
Python script to check wireless (802.11) capabilities based on authentication frame contents

This script uses scapy to listen for an authenciation frame from a client. It will then capture that frame and analyze it to create a report based on the capabilities reported by the client device. It can also be used to analyze the contents of a pcap file that contains a single authentication frame.

It has been developed to be used with the NanoPi that was created for the [WLPC Phoenix 2018 conference](https://www.wlanpros.com/resource/?wpv-category=2018-phoenix&wpv_aux_current_post_id=2623&wpv_view_count=464-TCPID2623). The NanoPi (also called the WLANPi) it a great little mini-Linux appliance that lends itself to a whole range of network testing applications. Find out more about the NanoPi at [http://wlanpi.com](http://wlanpi.com)

## Using the Script
To use the script on the NanoPi, transfer the wlan-client-capability.py script to the NanoPi. Ensure that a USB wireless adapter (e.g. Comfast CF-912AC) is plugged in to the NanoPi.

SSH to the NanoPi and place the wireless NIC on the channel you wish to monitor:

```
wlanpi@wlanpi:~/python$ sudo -s
[sudo] password for wlanpi: 
root@wlanpi:/home/wlanpi/python#
root@wlanpi:/home/wlanpi/python# airmon-ng check kill
root@wlanpi:/home/wlanpi/python# airodump wlan0 -c 48
root@wlanpi:/home/wlanpi/python# ./wlan_client_capability.py wlan0 any

```
## Usage

```
 Usage:

    wlan-client-capability.py -f <filename>
    wlan-client-capability.py -c <mon interface> < client_mac | any >
 
 ```
Example:

```
# capture frame for client aa:bb:cc:dd:ee:ff on interface wlan0
root@wlanpi:/home/wlanpi/python# wlan-client-capability.py -c wlan0 aa:bb:cc:dd:ee:ff

```

```
# capture frame for next client that send assocation frame on interface wlan0
root@wlanpi:/home/wlanpi/python# wlan-client-capability.py -c wlan0 aa:bb:cc:dd:ee:ff

```

```
# read last assocation frame captured by script (pcap file created automaticlaly each time script run)
root@wlanpi:/home/wlanpi/python# wlan-client-capability.py -f last_frame.pcap
```

(Note that this is work in progress and is not production ready.)

