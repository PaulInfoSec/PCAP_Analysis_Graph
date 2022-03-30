
import pickle
from enum import Enum import time
import matplotlib.pyplot as plt
import matplotlib.cm as cm
import numpy as np
from scapy.utils import RawPcapReader from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
#main function for reading pcap file and store in a pickle file, convert to a byte stream
#for performance improvement. Input is pcap file output is a pickle file def createpickle_pcap(pcap_file_in, pickle_file_out):
count = 0 interesting_packet_count = 0
# Each element of the list is a dictionary that contains fields of interest # from the packet.

packets_for_analysis = []
# Disregard LLC frames, type is the required ethernet data
for (pkt_data, pkt_metadata,) in RawPcapReader(pcap_file_in):
  count += 1
  ether_pkt = Ether(pkt_data)
  if 'type' not in ether_pkt.fields:
continue
if ether_pkt.type != 0x0800: # Only extract ipv4 continue
ip_pkt = ether_pkt[IP]
if ip_pkt.proto != 6:
# Only extract TCP packets continue
tcp_pkt = ip_pkt[TCP]
# Extract SYN packets only if str(tcp_pkt.flags) != "S" :
continue
# At this stage we have succesffuly filtered TCP packet with SYN flag # Increment number of packets
interesting_packet_count += 1
# This loop will only run for the first TCP packet if interesting_packet_count == 1:


# Appending both epoch + micro seconds to get epoch time in micro seconds to handle corect times
first_pkt_timestamp = float(f"{pkt_metadata.sec}.{pkt_metadata.usec}")
# Ordinal count refers to relative TCP packet number from 1st packet in pcap file first_pkt_ordinal = count
# Getting timestamp for last packet. This wil execute for every TCP packet received last_pkt_timestamp = float(f"{pkt_metadata.sec}.{pkt_metadata.usec}") last_pkt_ordinal = count
# Getting the relative time
this_pkt_relative_timestamp = last_pkt_timestamp - first_pkt_timestamp
# Create a dictionary of all relevent fields from each packet. # This information is stored in the pickle file
pkt_data = {}
pkt_data["src_ip"] = ip_pkt.src
pkt_data["dst_ip"] = ip_pkt.dst
pkt_data["src_port"] = tcp_pkt.sport
pkt_data["dst_port"] = tcp_pkt.dport
pkt_data['ordinal'] = last_pkt_ordinal pkt_data['relative_timestamp'] = this_pkt_relative_timestamp pkt_data['tcp_flags'] = str(tcp_pkt.flags)
# Appending this dict pkt_data to a list. packets_for_analysis.append(pkt_data)
# Opening a pickle file and sending the list of dictionaries in the file


with open(pickle_file_out, 'wb') as pickle_fd: pickle.dump(packets_for_analysis, pickle_fd)
# small function to handle X axis presentation even split of range def choose_step_range(time):
step = time / 6 return step
# function to plot the scatter chart, default values number of packets and time in seconds, added as arguments
# to the function
def create_visual(pickle_file_in, number_pkts=1000000, time_pkts=1000):
packets_for_analysis = []
count = 0
# Opening pickle file and reading bytes with open(pickle_file_in, 'rb') as pickle_fd:
packets_for_analysis = pickle.load(pickle_fd)
# Initialise three lists which for timestamps, ports, and IP's of the packets time = [];
port = [];
ip = []
index = 1
new_dict = {}
## add in additional colours List of colors to be used for scatter plots. # individual colour for each source IP
colors = ["b", "g", "r", "c", "m", "y", "k"]


# Initializing an empty plot for plotting, size of chart plt.figure(figsize=(15, 15))
#logic to manage timestamps
for pkt_data in packets_for_analysis:
count += 1
if (pkt_data['relative_timestamp'] > float(time_pkts)) or (count > number_pkts):
continue
time_stamp = pkt_data['relative_timestamp']
src_ip = pkt_data["src_ip"]
# This loop will plot the scatter chart. Logic here is to use unique labels # plus previous information for the source IPs
if pkt_data["src_ip"] not in new_dict.keys(): new_dict[src_ip] = index
val = new_dict[src_ip]
if val > len(colors):
color = colors[-1] else:
color = colors[val]
plt.scatter(x=pkt_data["relative_timestamp"], y=pkt_data["dst_port"], label=src_ip, color=color, s=200)
index += 1 else:
val = new_dict[src_ip]
plt.scatter(x=pkt_data["relative_timestamp"], y=pkt_data["dst_port"], color=colors[val], s=200)


# Legend details
plt.legend(loc=(1.04, 0.5), title="Source IP Address", fontsize=50) # set names for X and Y axis
plt.xlabel("Time in seconds", fontsize=35)
plt.ylabel("TCP Destination Port", fontsize=35)
# Setting Y ranges for the plots to show first, max and interval range plt.yticks(np.arange(0, 1000, 100))
if time_pkts > time_stamp:
step_time = time_stamp else:
step_time = time_pkts
# managing the x axis division to show first, max and interval range
step = choose_step_range(step_time) plt.xticks(np.arange(0, time_stamp + 1, int(step)))
#Setting title for the scatter plot
plt.title("TCP SYN attempts over time", fontsize=50)
# Set fontsizes
ax = plt.gca()
ax.tick_params(axis = 'both', which = 'major', labelsize = 25) ax.tick_params(axis = 'both', which = 'minor', labelsize = 25)
plt.show()


createpickle_pcap(r"/Users/****/Desktop/pcap/Networkcapture2.pcap", "pcap_picklefile")
#create_visual("pcap_picklefile")
create_visual("pcap_picklefile", number_pkts=300) #create_visual("pcpap_picklefile", number_pkts=200, time_pkts=10)
