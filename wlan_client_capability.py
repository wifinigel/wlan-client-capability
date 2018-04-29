#!/usr/bin/python
from __future__ import print_function, unicode_literals, division
import sys
import textwrap
from scapy.all import *
import os

# we must be root to run this script - exit with msg if not
if not os.geteuid()==0:
    print("\n#####################################################################################")
    print("You must be root to run this script (use 'sudo wlan_client_capability.py') - exiting" )
    print("#####################################################################################\n")
    exit()

#  assoc req frame tag list numbers

# power information
power_min_max = "33"

# channels supported by client
supported_channels = "36"

# 802.11n support info
ht_capabilities    = "45"

# 802.11r support info
ft_capabilities    = "54"

# 802.11k support info
rm_capabilities    = "70"

# 802.11v
ext_capabilities   = "127"

# 802.11ac support info
vht_capabilities   = "191"

def analyze_frame(assoc_req_frame, silent_mode=False, required_client=''):

    if not assoc_req_frame.haslayer(Dot11):
    
        if not silent_mode:
            print("Sorry, this does not look like an 802.11 frame, exiting...")
        
        return(False)

    if not assoc_req_frame.haslayer(Dot11AssoReq):
    
        if not silent_mode:
            print("Sorry, this does not look like an Association frame, exiting...")
        
        return(False)


    # pull off the RadioTap, Dot11 & Dot11AssoReq layers
    dot11 = assoc_req_frame.payload
    frame_src_addr = dot11.addr2
    
    if required_client:
    
        # we have specified a client we are interested in, but this isn't it
        if (required_client != 'any') and (required_client.lower() != frame_src_addr):
            print("Assoc request detected, wrong client: " + dot11.addr2 + " - (req client = " + required_client + ")")
            return(False)
    
    capabilites = dot11.getfieldval("cap")
    dot11_assoreq = dot11.payload.payload
    dot11_elt = dot11_assoreq

    # common dictionary to store all tag lists
    dot11_elt_dict = {}

    # analyse the tag lists & store in a dictionary
    while dot11_elt:

        # get tag number
        dot11_elt_id = str(dot11_elt.ID)

        # get tag list
        dot11_elt_info = dot11_elt.getfieldval("info")
        
        # covert tag list in to useable format (decimal list of values)
        dec_array = map(ord, str(dot11_elt_info))
        #hex_array = map(hex, dec_array)

        # store each tag list in a common tag dictionary
        dot11_elt_dict[dot11_elt_id] = dec_array
        
        # move to next layer - end of while loop
        dot11_elt = dot11_elt.payload

    # start report
    print('\n')
    print('-' * 60)
    print("Client capabilites report - Client MAC: " + frame_src_addr)
    print('-' * 60)
    
    capability_dict = {}
    
    # check if 11n supported
    if ht_capabilities in dot11_elt_dict.keys():
        capability_dict['802.11n'] = 'Supported'
        
        spatial_streams = 0
        
        # mcs octets 1 - 4 indicate # streams supported (up to 4 streams only)
        for mcs_octet in range(3, 7):
        
            mcs_octet_value = dot11_elt_dict[ht_capabilities][mcs_octet]
        
            if (mcs_octet_value & 255):
                spatial_streams += 1
        
        capability_dict['802.11n'] = 'Supported (' + str(spatial_streams) + 'ss)'
    else:
        capability_dict['802.11n'] = 'Not reported*'
        
    # check if 11ac supported
    if vht_capabilities in dot11_elt_dict.keys():
        
        mcs_upper_octet = dot11_elt_dict[vht_capabilities][5]
        mcs_lower_octet = dot11_elt_dict[vht_capabilities][4]
        mcs_rx_map = (mcs_upper_octet * 256) + mcs_lower_octet
        
        # define the bit pair we need to look at
        spatial_streams = 0
        stream_mask = 3

        # move through each bit pair & test for '10' (stream supported)
        for mcs_bits in range(1,9):
                    
            if (mcs_rx_map & stream_mask) != stream_mask:
            
                # stream mask bits both '1' when mcs map range not supported
                spatial_streams += 1
            
            # shift to next mcs range bit pair (stream)
            stream_mask = stream_mask * 4
        
        capability_dict['802.11ac'] = 'Supported (' + str(spatial_streams) + 'ss)'

    else:
        capability_dict['802.11ac'] = 'Not reported*'
        
    # check if 11k supported
    if rm_capabilities in dot11_elt_dict.keys():
        capability_dict['802.11k'] = 'Supported'
    else:
        capability_dict['802.11k'] = 'Not reported*'

    # check if 11r supported
    if ft_capabilities in dot11_elt_dict.keys():
        capability_dict['802.11r'] = 'Supported'
    else:
        capability_dict['802.11r'] = 'Not reported*'

    # check if 11v supported
    if ext_capabilities in dot11_elt_dict.keys():
    
        ext_cap_list = dot11_elt_dict[ext_capabilities]
        
        capability_dict['802.11v'] = 'Not reported*'
    
        # check octet 3 exists
        if 3 <= len(ext_cap_list):

            # bit 4 of octet 3 in the extended capabilites field
            octet3 = ext_cap_list[2]
            bss_trans_support = int('00001000', 2)
            
            # 'And' octet 3 to test for bss transition support
            if octet3 & bss_trans_support:
                capability_dict['802.11v'] = 'Supported'
    
    # check if power capabilites supported
    if power_min_max in dot11_elt_dict.keys():

        # octet 3 of power capabilites
        max_power = dot11_elt_dict[power_min_max][1]
        
        capability_dict['Max_Power'] = str(max_power) + " dBm"
    
    # print out capabilities (in nice format)
    for key in capability_dict.keys():
        print("{:<20} {:<20}".format(key, capability_dict[key]))

    # check supported channels
    channel_sets_list = dot11_elt_dict[supported_channels]
    channel_list = []
    
    while (channel_sets_list):
    
        start_channel = channel_sets_list.pop(0)
        channel_range = channel_sets_list.pop(0)
        
        for i in range(channel_range):
            channel_list.append(start_channel + (i * 4))
    
    print("\nReported supported channel list:\n")
    channel_list_str = ', '.join(map(str, channel_list))
    print(textwrap.fill(channel_list_str, 60))
    
    print("\n\n" + textwrap.fill("* Reported client capabilities are dependant on these features being available from the wireless network at time of client association", 60) + "\n\n")
    
    return True

def PktHandler(frame):
    
    required_client = sys.argv[3]
    wrpcap('last_frame.pcap', [frame])
    # attempt to analyze frame
    if (analyze_frame(frame, True, required_client)):
    
        # we got an assocation request frame and analyzed it OK - dump & exit
        wrpcap('last_frame.pcap', [frame])
        exit()
    else:
        # frame incorrect type, lets try again...
        return

def Usage():
    print("\n Usage:\n")
    print("    wlan_client_capability.py -f <filename>")
    print("    wlan_client_capability.py -c <mon interface> < client_mac | any >\n")
    exit()

#################################################
# Main
#################################################
def main():
    if len(sys.argv) < 2:
        Usage()

    # Analyze client capabilities from pcap file
    if sys.argv[1] == '-f':
        # file name we are going to analyze
        filename = sys.argv[2]

        # read in the pcap file
        frame = rdpcap(filename)

        # extract the first frame object
        assoc_req_frame = frame[0]

        # perform analysis
        analyze_frame(assoc_req_frame)

    # Analyze client capabilities of client capture association frame
    elif sys.argv[1] == '-c':
        # capture live
        mon_iface = sys.argv[2]
        client_mac = sys.argv[3]
        
        print("\n Listening for client association frames...\n")
        
        sniff(iface=mon_iface, prn=PktHandler)
    else:
        Usage()

if __name__ == "__main__":
    main()
