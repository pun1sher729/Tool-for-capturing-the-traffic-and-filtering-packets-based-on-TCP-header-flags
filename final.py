from scapy.all import *
from colorama import init, Fore

# initialize colorama
init()

# define colors
GREEN = Fore.GREEN
RED   = Fore.RED
RESET = Fore.RESET

interface = "wlp4s0"
path = "test2.pcap"
flags = ['ack', 'urg', 'push', 'syn', 'fin']

#Captures traffic to a file
def capture_to_file(path:str, number_of_packets:int, fltr:str):
    capture = sniff(iface=interface, count=number_of_packets, filter=fltr)
    wrpcap(path, capture)

#Reads packets from a pcap file
def read_from_file(path:str):
    pkts = rdpcap(path)
    return pkts

#Returns flag filter for OR option
def or_flag_filter(sel_flags:list):
    flag_filter = "tcp[tcpflags]&("
    n = len(sel_flags)
    for flag in range(n):
        if sel_flags[flag].lower() in flags:
            if flag != n-1:
                flag_filter += f"tcp-{sel_flags[flag].lower()}|"
            else:
                flag_filter += f"tcp-{sel_flags[flag].lower()}"
    flag_filter += ") != 0"

    return flag_filter

#Returns flag filter for AND option
def and_flag_filter(sel_flags:list):
    fltr = ""
    n = len(sel_flags)
    for flag in range(n):
        if sel_flags[flag].lower() in flags:
            if flag != n-1:
                fltr += f"tcp-{sel_flags[flag].lower()}|"
            else:
                fltr += f"tcp-{sel_flags[flag].lower()}"
    flag_filter = f"tcp[tcpflags]&({fltr}) == ({fltr})"

    return flag_filter

#Returns all the flags present in a packet
def find_flags_in_packet(flags):
    out = ""
    if(flags & 0x01):
       out += "FIN "
    if(flags & 0x02):
       out += "SYN "
    if(flags & 0x08):
       out += "PSH "
    if(flags & 0x10):
       out += "ACK "
    if(flags & 0x20):
       out += "URG "

    return out.strip()

#Check if teh input packets are present in the flag
def check_for_flag(sel_flags:list, flags:list):
    count = 0
    for i in sel_flags:
        if i in flags:
            count += 1
    
    if count == len(sel_flags):
        return 1
    return 0

#Caputres and prints packet information
def print_capt_packets_info(path:str, num_of_pkts:int, flag_filter:str):
    print("\nCapturing Packets...")
    capture_to_file(path, num_of_pkts, flag_filter)

    capture = read_from_file(path)

    for packet in capture:
        try:
            print(f"Source IP: {GREEN}{packet['IP'].src}{RESET}")
            print(f"Destination IP: {GREEN}{packet['IP'].dst}{RESET}")
        except:
            print(f"Source IP: {GREEN}{packet['IPv6'].src}{RESET}")
            print(f"Destination IP: {GREEN}{packet['IPv6'].dst}{RESET}")
        print(f"Source Port: {GREEN}{packet['TCP'].sport}{RESET}")
        print(f"Destination Port: {GREEN}{packet['TCP'].dport}{RESET}")
        print(f"Flags: {GREEN}{find_flags_in_packet(packet['TCP'].flags)}{RESET}")
        print()


#Reads from a pcap file and prints packet information
def print_read_packets_info(path:str, sel_flags:list):
    capture = read_from_file(path)
    sel_flags  = [i.upper() for i in sel_flags]
    tcp_count = 0
    req_count = 0
    for packet in capture:
        if packet.haslayer("TCP"):
            tcp_count += 1
            flags = find_flags_in_packet(packet['TCP'].flags).split(" ")
            if check_for_flag(sel_flags, flags):
                req_count+=1
                try:
                    print(f"Source IP: {GREEN}{packet['IP'].src}{RESET}")
                    print(f"Destination IP: {GREEN}{packet['IP'].dst}{RESET}")
                except:
                    print(f"Source IP: {GREEN}{packet['IPv6'].src}{RESET}")
                    print(f"Destination IP: {GREEN}{packet['IPv6'].dst}{RESET}")
                print(f"Source Port: {GREEN}{packet['TCP'].sport}{RESET}")
                print(f"Destination Port: {GREEN}{packet['TCP'].dport}{RESET}")
                print(f"Flags: {GREEN}{find_flags_in_packet(packet['TCP'].flags)}{RESET}")
                print()
                
    print(f"Total TCP packets in file: {GREEN}{tcp_count}{RESET}")
    print(f"Total packets with input flags: {GREEN}{req_count}{RESET}")

def main():
    sel_flags = input(f"{RED}\nSelect the TCP flag(s): ACK URG PUSH SYN FIN \n{RESET}").split()

    opt = int(input(f"\n{RED}Select (1)for Capturing Packets (2)for Reading from a exisisting file{RESET}\n"))

    if opt == 1:
        num_of_pkts = int(input(f"\n{RED}Enter the number of packets to be captured: {RESET}"))

        print(f"{RED}Select\n(1)OR(Packets are captured if one of the input flags is present)\n(2)AND(Packets are captured if all input flags are present){RESET}")
        fltr_opt = int(input(f"{RED}Option: {RESET}"))

        if fltr_opt == 1:
            flag_filter = or_flag_filter(sel_flags)
        elif fltr_opt == 2:
            flag_filter = and_flag_filter(sel_flags)
        
        print_capt_packets_info(path, num_of_pkts, flag_filter)
    
    if opt == 2:
        rd_path = input(f"{RED}Enter path to pcap file: {RESET}")
        print_read_packets_info(rd_path, sel_flags)

if '__name__' == main():
    main()