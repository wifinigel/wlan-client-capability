#!/usr/bin/python

from fakeap import *
from scapy.layers.dot11 import *
import subprocess
from types import MethodType
import textwrap
import sys
import os

# we must be root to run this script - exit with msg if not
if not os.geteuid()==0:
    print("\n#####################################################################################")
    print("You must be root to run this script (use 'sudo wlan_client_capability.py') - exiting" )
    print("#####################################################################################\n")
    sys.exit()

# define fake AP parameters
fakeap_channel = 36
fakeap_ssid = 'scapy'

# set dir to dump capture frames
dump_dir = '/var/www/html/pcap'

# check if dump dir exists, create if not
if not os.path.isdir(dump_dir):
    try:
        os.mkdir(dump_dir)
    except Exception as ex:
        print("Trying to create directory: {} but having an issue: {}".format(dump_dir, ex))
        print("Exiting...")
        sys.exit()

# set up the WLAN adapter
if_cmds = [
    'ifconfig wlan0 down',
    'iwconfig wlan0 mode monitor',
    'ifconfig wlan0 up',
    'iw wlan0 set channel ' + str(fakeap_channel)
]

# run WLAN adapter setup commands & check for failures
for cmd in if_cmds:
    try:            
        subprocess.check_output(cmd + " 2>&1", shell=True)
    except Exception as ex:
        print("Error setting wlan interface config:")
        print(ex)
        sys.exit()

#  assoc req frame tag list numbers

# power information
POWER_MIN_MAX_TAG = "33"

# channels supported by client
SUPPORTED_CHANNELS_TAG = "36"

# 802.11n support info
HT_CAPABILITIES_TAG    = "45"

# 802.11r support info
FT_CAPABILITIES_TAG    = "54"

# 802.11k support info
RM_CAPABILITIES_TAG    = "70"

# 802.11v
EXT_CAPABILITIES_TAG   = "127"

# 802.11ac support info
VHT_CAPABILITIES_TAG   = "191"

# list of detected clients
detected_clients = []

def analyze_frame_cb(self, packet, silent_mode=False, required_client=''):

        analyze_frame(packet, silent_mode, required_client)

def analyze_frame(packet, silent_mode=False, required_client=''):
    
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
    mac_addr = frame_src_addr.replace(':', '-', 5)
    dump_filename = dump_dir + '/' + mac_addr + '.pcap'
    wrpcap(dump_filename, [packet])  
    
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

    # analyse the 802.11 frame tag lists & store in a dictionary
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
    
    # dictionary to store capabilities as we decode them
    capability_dict = {}
    
    # check if 11n supported
    if HT_CAPABILITIES_TAG in dot11_elt_dict.keys():
        capability_dict['802.11n'] = 'Supported'
        
        spatial_streams = 0
        
        # mcs octets 1 - 4 indicate # streams supported (up to 4 streams only)
        for mcs_octet in range(3, 7):
        
            mcs_octet_value = dot11_elt_dict[HT_CAPABILITIES_TAG][mcs_octet]
        
            if (mcs_octet_value & 255):
                spatial_streams += 1
        
        capability_dict['802.11n'] = 'Supported (' + str(spatial_streams) + 'ss)'
    else:
        capability_dict['802.11n'] = 'Not reported*'
        
    # check if 11ac supported
    if VHT_CAPABILITIES_TAG in dot11_elt_dict.keys():
        
        # Check for number streams supported
        mcs_upper_octet = dot11_elt_dict[VHT_CAPABILITIES_TAG][5]
        mcs_lower_octet = dot11_elt_dict[VHT_CAPABILITIES_TAG][4]
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
        mu_octet = dot11_elt_dict[VHT_CAPABILITIES_TAG][2]
        su_octet = dot11_elt_dict[VHT_CAPABILITIES_TAG][1]
        
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
    if RM_CAPABILITIES_TAG in dot11_elt_dict.keys():
        capability_dict['802.11k'] = 'Supported'
    else:
        capability_dict['802.11k'] = 'Not reported* - treat with caution, many clients lie about this'

    # check if 11r supported
    if FT_CAPABILITIES_TAG in dot11_elt_dict.keys():
        capability_dict['802.11r'] = 'Supported'
    else:
        capability_dict['802.11r'] = 'Not reported*'

    # check if 11v supported
    capability_dict['802.11v'] = 'Not reported*'
    
    if EXT_CAPABILITIES_TAG in dot11_elt_dict.keys():
    
        ext_cap_list = dot11_elt_dict[EXT_CAPABILITIES_TAG]
    
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
    
    if POWER_MIN_MAX_TAG in dot11_elt_dict.keys():

        # octet 3 of power capabilites
        max_power = dot11_elt_dict[POWER_MIN_MAX_TAG][1]
        
        capability_dict['Max_Power'] = str(max_power) + " dBm"

    # check supported channels
    if SUPPORTED_CHANNELS_TAG in dot11_elt_dict.keys():
        channel_sets_list = dot11_elt_dict[SUPPORTED_CHANNELS_TAG]
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
        
        capability_dict['Supported_Channels'] = ', '.join(map(str, channel_list))
        
    else:
        capability_dict['Supported_Channels'] =  "Not reported"
    
    # print our report to stdout
    text_report(frame_src_addr, capability_dict)
    
    return True

def text_report(frame_src_addr, capability_dict):

    # start report
    print('\n')
    print('-' * 60)
    print("Client capabilites report - Client MAC: " + frame_src_addr)
    print('-' * 60)
    
    # print out capabilities (in nice format)
    capabilities = ['802.11k', '802.11r', '802.11v', '802.11n', '802.11ac', 'Max_Power', 'Supported_Channels']
    for key in capabilities:
        print("{:<20} {:<20}".format(key, capability_dict[key]))
    
    print("\n\n" + textwrap.fill("* Reported client capabilities are dependant on these features being available from the wireless network at time of client association", 60) + "\n\n")

    return True

def run_fakeap(wlan_if, fakeap_ssid):

    ap = FakeAccessPoint('wlan0', fakeap_ssid)
    my_callbacks = Callbacks(ap)

    my_callbacks.cb_recv_pkt = MethodType(my_recv_pkt, my_callbacks)
    my_callbacks.cb_analyze_frame = MethodType(analyze_frame_cb, my_callbacks)
    ap.callbacks = my_callbacks

    # set fake AP channel
    ap.channel = fakeap_channel
    # lower the beacon interval used to account for execution time of script
    ap.beaconTransmitter.interval = 0.05
    ap.run()

def my_recv_pkt(self, packet):  # We override recv_pkt to include a trigger for our callback

    if packet.haslayer(Dot11AssoReq):
        self.cb_analyze_frame(packet) 
    self.recv_pkt(packet)

def usage():
    print("\n Usage:\n")
    print("    wlan_client_capability.py --all")
    print("    wlan_client_capability.py --pcap <filename>")
    print("    wlan_client_capability.py --client <mon interface> < client_mac | any >\n")
    exit()

def main():

    # Default action run fakeap & analyze assoc req frames
    if len(sys.argv) < 2:
        run_fakeap('wlan0', fakeap_ssid)
        
    elif sys.argv[1] == '--all':
        run_fakeap('wlan0', fakeap_ssid)
    
    # Analyze client capabilities from pcap file
    elif sys.argv[1] == '--pcap':
        # file name we are going to analyze
        filename = sys.argv[2]

        # read in the pcap file
        frame = rdpcap(filename)

        # extract the first frame object
        assoc_req_frame = frame[0]

        # perform analysis
        analyze_frame(assoc_req_frame)

    # Analyze client capabilities of client capture association frame
    elif sys.argv[1] == '--client':
        # capture live
        mon_iface = sys.argv[2]
        client_mac = sys.argv[3]
        
        print("\n Listening for client association frames...\n")
        
        sniff(iface=mon_iface, prn=PktHandler)
     # Analyze client capabilities of client capture association frame
    elif sys.argv[1] == '--help':
        usage()
    
    else:
        Usage()

    
        
if __name__ == "__main__":
    main()