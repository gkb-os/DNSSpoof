import netfilterqueue
import scapy.all as scapy 
import subprocess

#subprocess.call("iptables -I INPUT -j NFQUEUE --queue-num 0")
#ubprocess.call("iptables -I OUTPUT -j NFQUEUE --queue-num 0")
try:
    def process_packet(packet):
        s_pkt= scapy.IP(packet.get_payload())
        if s_pkt.haslayer(scapy.Raw):
            if s_pkt[scapy.TCP].dport == 80:
                print(s_pkt.show())
            elif s_pkt[scapy.TCP].sport == 80:
                print(s_pkt.show())

        packet.accept()                                   

    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)
    queue.run()

except KeyboardInterrupt:
    print("[+] Ctrl^C was pressed.... Stopping!")
