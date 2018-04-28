# wlan-client-capability
Python script to check wireless (802.11) capabilities based on authentication frame contents

This script uses scapy to listen for an authenciation frame from a client. It will then capture that frame and analyze it to create a report based on the capabilities reported by the client device. It can also be used to analyze the contents of a pcap file that contains a single authentication frame.

It has been developed to be used with the NanoPi that was created for the [WLPC Phoenix 2018 conference](https://www.wlanpros.com/resource/?wpv-category=2018-phoenix&wpv_aux_current_post_id=2623&wpv_view_count=464-TCPID2623). The NanoPi (also called the WLANPi) it a great little mini-Linux appliance that lends itself to a whole range of network testing applications. Find out more about the NanoPi at [http://wlanpi.com](http://wlanpi.com)

## Using the Script
To use the script on the NanoPi, transfer the wlan-client-capability.py script to the NanoPi (make it executable with "chmod a+x wlan_client_capability.py"). Ensure that a USB wireless adapter (e.g. Comfast CF-912AC) is plugged in to the NanoPi.

SSH to the NanoPi and place the wireless NIC on the channel you wish to monitor:

```
wlanpi@wlanpi:~/python$ sudo -s
[sudo] password for wlanpi: 
root@wlanpi:/home/wlanpi/python#
root@wlanpi:/home/wlanpi/python# airmon-ng check kill
root@wlanpi:/home/wlanpi/python# airodump-ng wlan0 -c 48   (Specify channel required with '-c'. Kill with ctlr-c once running)
root@wlanpi:/home/wlanpi/python# ./wlan_client_capability.py wlan0 any

```
## Usage

```
 Usage:

    wlan-client-capability.py -f <filename>
    wlan-client-capability.py -c <mon interface> < client_mac | any >
 
 ```
### Examples:

```
# capture frame for client aa:bb:cc:dd:ee:ff on interface wlan0
root@wlanpi:/home/wlanpi/python# wlan-client-capability.py -c wlan0 aa:bb:cc:dd:ee:ff

```

```
# capture frame for next client that send assocation frame on interface wlan0
root@wlanpi:/home/wlanpi/python# wlan-client-capability.py -c wlan0 any

```

```
# read last assocation frame captured by script (pcap file created automaticlaly each time script run)
root@wlanpi:/home/wlanpi/python# wlan-client-capability.py -f last_frame.pcap
```

## Screenshot

![Screenshot](https://github.com/wifinigel/wlan-client-capability/blob/master/screenshot.PNG)

## Caveats
- Note that this is work in progress and is not production ready and is not fully tested or guaranteed to report accurate info. **You have been warned**
- A client will generally only report the capabilities it has that match the network it associates to. If you want the client to report all of its capabilities, it **must** be associating with a network that supports those capabilities. **You have been warned**

## Credits
Much of the source information for this project came from Mike Albano's excellent article: [What do "your" WiFi clients support?
](http://www.mikealbano.com/2016/02/what-do-your-wifi-clients-support.html), together with supporting information referenced in the article.
