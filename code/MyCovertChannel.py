from CovertChannelBase import CovertChannelBase
import random
from scapy.all import *
import time
from scapy.all import IP, UDP, DNS, DNSQR, send
"""
dikkat edilmesi gerekenler:
+sender sürekli şekilde while döngüsünde olup dns paket gönderecek, receiver sniffleyecek. receiver snifflerken o sırada sender göndermemesi
gerektiği halde yine DNS paketi gönderirse karışıklık olabilir. send fonksiyonuna sleep koymak belli bir yere kadar işe yarayabilir, belki
bazı uç caselerde daha akıllıca senkronizasyon gerekebilir.
+bu implementasyon 3 dknın üzerinde sürüyor, bunun optimize edilmesi lazım
+send fonksiyonu yerine send_and_receive (sr) kullanılarak da senkronizayon bakımından daha da geliştirebiliriz
"""
class MyCovertChannel(CovertChannelBase):
    def __init__(self):
        pass

    def send(self, log_file_name):
        binary_message = self.generate_random_binary_message_with_logging(log_file_name)
        checking_for_dot_character = ""
        i = 0
        
        while True:
            if binary_message[i] == '0':
                #send two consecutive DNS packets with same RA flag
            	#here we implemented randint function to choose the flag randomly, so that the covert channel can be more powerful
                #random_flag = random.randint(0, 1)
                self.send_dns_packet(ra_flag=0)
                self.send_dns_packet(ra_flag=0)
            elif binary_message[i] == '1':
                #send two consecutive DNS packets with different RA flag
                #here we implemented randint function to choose the flag randomly, so that the covert channel can be more powerful
                #random_flag = random.randint(0, 1)
                self.send_dns_packet(ra_flag=0)
                self.send_dns_packet(ra_flag=1)
            
            checking_for_dot_character += binary_message[i]
            #check fo end of the message (dot character)
            if len(checking_for_dot_character) == 8:
                if checking_for_dot_character == "00101110": #if checking_for_dot_character equals to dot character
                    print("ENNDDDDD")
                    break
                checking_for_dot_character = ""
            #it is here for if there is no dot but there will be so it is not necessary actually
            i += 1
            if i >= len(binary_message):
                break

    def send_dns_packet(self, ra_flag):
        #burada rd -recursion desired- ve qd field'larını boş bırakmak daha mı mantıklı olur covert channel' ın ruhuna uygun olması için??
        dns_query = IP(dst="172.18.0.3")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="google.com"))
        
        #setting ra flag in the DNS packet
        if ra_flag == 1:
            dns_query[DNS].ra =1
        else:
            dns_query[DNS].ra =0

        send(dns_query, verbose=False)
        time.sleep(0.1)  #small delay to ensure proper sequencing

    def receive(self, log_file_name):
        decoded_message = ""
        checking_for_dot_character=""
        received_message=""
        while True:
            #listen to the upcoming two dns packets
            packets = self.listen_for_dns_packets()
            
            #if two consecutive received dns packets have the same ra flag, then decode it as '0'
            #otherwise decode it as '1'
            if packets[0][DNS].ra == packets[1][DNS].ra:
                decoded_message += '0'
                checking_for_dot_character+= '0'
            else:
                decoded_message += '1'
                checking_for_dot_character+='1'
            
            #check if the dot character is encountered
            if len(checking_for_dot_character) == 8:
                if checking_for_dot_character == "00101110":
                    received_message+=self.convert_eight_bits_to_character(checking_for_dot_character)
                    break
                received_message+=self.convert_eight_bits_to_character(checking_for_dot_character)
                checking_for_dot_character=""
        
        self.log_message(received_message, log_file_name)

    def listen_for_dns_packets(self):
        packets = sniff(filter="udp and host 172.18.0.2 and port 53", count=2)
        return packets
