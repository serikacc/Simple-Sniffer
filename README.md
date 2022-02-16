# Simple-Sniffer
A simple sniffer base on Qt
## Environment
Windows10
Qt 5.10.1
Qt Create 4.6.0
WinPcap4.1.3
## Function
1. ARP sending packets for ARP spoofing
2. Ethernet frame header analysis
3. ARP packet analysis
4. IP packet header parsing
5. TCP packet header parsing
6. UDP packet header parsing
7. ICMP message parsing
8. Packet filtering
9. Packet Statistics
10. Packet saving
11. Operation interface
## System Design
### Main Module
The main module is used to select the adapter that needs to be monitored, display the content of the data packet in real time, set the filter,
and for the selected data packets, the data packets can be analyzed in detail, and the number and types of data packets can be counted, and then display them.
### Packet Sending Module
The packet sending module is used to send specific data packets for ARP spoofing.
### Packet Capture Module
The packet capture module is used to write the captured packets that meet the requirements to a file system according to the filter settings
system, analyze the data packets, and send the analysis results back to the main module to be displayed in real time.
