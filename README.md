# Tool-for-capturing-the-traffic-and-filtering-packets-based-on-TCP-header-flags
Python based tool to capture and read packets based on TCP flags

Features:
- Live capture packets based on TCP flags
- 2 options in live capture: OR and AND
  - OR option: Captures packets with atleast 1 flag from the input
  - AND option: Captures packets with all flags in the input
- Read from a existing pcap file


__Scapy may need sudo permission to run the python file__
