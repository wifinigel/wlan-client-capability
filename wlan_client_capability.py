#!/usr/bin/python

from fakeap import *
from scapy.layers.dot11 import *
import subprocess
from types import MethodType
import textwrap
import sys

# Set channel of fake AP
channel = 36

if_cmds = [
    'ifconfig wlan0 down',
    'iwconfig wlan0 mode monitor',
    'ifconfig wlan0 up',
    'iw wlan0 set channel ' + str(channel)
]

# run commands & check for failures
for cmd in if_cmds:
    try:            
        subprocess.check_output(cmd + " 2>&1", shell=True)
    except Exception as ex:
        print("Error setting wlan interface config:")
        print(ex)
        sys.exit()

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

detected_clients = []

def analyze_frame(self, packet, silent_mode=False, required_client=''):
    
    # pull off the RadioTap, Dot11 & Dot11AssoReq layers
    dot11 = packet.payload
    frame_src_addr = dot11.addr2
    
    if frame_src_addr in detected_clients:
        
        # already analysed this client, moving on
        print("Detected " + str(frame_src_addr) + " again, ignoring..." )
        return(False)
    
    # add client to detected clients list
    detected_clients.append(frame_src_addr)
        
    # dump out the frame to a file
    wrpcap(frame_src_addr.replace(':', '-', 5) + '.pcap', [packet])  
    
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
        
        # Check for number streams supported
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
        
        vht_support = 'Supported (' + str(spatial_streams) + 'ss)'
        
        # check for SU & MU beam formee support
        mu_octet = dot11_elt_dict[vht_capabilities][2]
        su_octet = dot11_elt_dict[vht_capabilities][1]
        
        beam_form_mask = 8
        
        # bit 4 indicates support for both octets (1 = supported, 0 = not supported) 
        if (su_octet & beam_form_mask):
            vht_support += ", SU BF supported"
        else:
            vht_support += ", SU BF not supported"
         
        if (mu_octet & beam_form_mask):
            vht_support += ", MU BF supported"
        else:
            vht_support += ", MU BF not supported"
        
        capability_dict['802.11ac'] = vht_support

    else:
        capability_dict['802.11ac'] = 'Not reported*'
        
    # check if 11k supported
    if rm_capabilities in dot11_elt_dict.keys():
        capability_dict['802.11k'] = 'Supported'
    else:
        capability_dict['802.11k'] = 'Not reported* - treat with caution, many clients lie about this'

    # check if 11r supported
    if ft_capabilities in dot11_elt_dict.keys():
        capability_dict['802.11r'] = 'Supported'
    else:
        capability_dict['802.11r'] = 'Not reported*'

    # check if 11v supported
    capability_dict['802.11v'] = 'Not reported*'
    
    if ext_capabilities in dot11_elt_dict.keys():
    
        ext_cap_list = dot11_elt_dict[ext_capabilities]
    
        # check octet 3 exists
        if 3 <= len(ext_cap_list):

            # bit 4 of octet 3 in the extended capabilites field
            octet3 = ext_cap_list[2]
            bss_trans_support = int('00001000', 2)
            
            # 'And' octet 3 to test for bss transition support
            if octet3 & bss_trans_support:
                capability_dict['802.11v'] = 'Supported'
    
    # check if power capabilites supported
    capability_dict['Max_Power'] = 'Not reported'
    
    if power_min_max in dot11_elt_dict.keys():

        # octet 3 of power capabilites
        max_power = dot11_elt_dict[power_min_max][1]
        
        capability_dict['Max_Power'] = str(max_power) + " dBm"
    
    # print out capabilities (in nice format)
    for key in capability_dict.keys():
        print("{:<20} {:<20}".format(key, capability_dict[key]))

    # check supported channels
    if supported_channels in dot11_elt_dict.keys():
        channel_sets_list = dot11_elt_dict[supported_channels]
        channel_list = []
        
        while (channel_sets_list):
        
            start_channel = channel_sets_list.pop(0)
            channel_range = channel_sets_list.pop(0)
            
            # check for if 2.4Ghz or 5GHz
            if start_channel > 14:
                channel_multiplier = 4
            else:
                channel_multiplier = 1
                
            
            for i in range(channel_range):
                channel_list.append(start_channel + (i * channel_multiplier))
        
        print("\nReported supported channel list:\n")
        channel_list_str = ', '.join(map(str, channel_list))
        print(textwrap.fill(channel_list_str, 60))
        
    else:
        print("{:<20} {:<20}".format("Supported channels", "Not reported"))
    
    print("\n\n" + textwrap.fill("* Reported client capabilities are dependant on these features being available from the wireless network at time of client association", 60) + "\n\n")
    
    return True

def my_recv_pkt(self, packet):  # We override recv_pkt to include a trigger for our callback

    if packet.haslayer(Dot11AssoReq):
        self.cb_analyze_frame(packet) 
    self.recv_pkt(packet)

def main():
    ap = FakeAccessPoint('wlan0', 'scapy')
    my_callbacks = Callbacks(ap)

    my_callbacks.cb_recv_pkt = MethodType(my_recv_pkt, my_callbacks)
    my_callbacks.cb_analyze_frame = MethodType(analyze_frame, my_callbacks)
    ap.callbacks = my_callbacks

    # This seems to set the channel fine...
    ap.channel = channel
    # lower the beacon interval used to account for execution time of script
    ap.beaconTransmitter.interval = 0.05
    ap.run()
        
if __name__ == "__main__":
    main()