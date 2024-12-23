from CovertChannelBase import CovertChannelBase
from scapy.all import IP, UDP, DNS, DNSQR, send, sniff
import time

class MyCovertChannel(CovertChannelBase):
    def __init__(self):
        super().__init__()
        self.dst_ip = "172.18.0.3"
        self.src_ip = "172.18.0.2"
        self.dns_port = 53
        self.current_seq = 0

    def send_dns_packet(self, ra_flag):
        """Send DNS packet with sequence number"""
        dns_query = IP(dst=self.dst_ip)/UDP(dport=self.dns_port)/DNS(
            id=self.current_seq,  # Use DNS ID for sequence
            qr=0,  # Query
            ra=ra_flag
        )
        
        # Send packet and increment sequence
        super().send(dns_query)
        self.current_seq = (self.current_seq + 1) % 65535
        time.sleep(0.005)  # Minimal delay for network stability

    def send(self, log_file_name):
        start = time.time()
        binary_message = self.generate_random_binary_message_with_logging(log_file_name)
        print(f"Starting transmission of {len(binary_message)} bits")
        
        # Send initial sync packet
        sync_packet = IP(dst=self.dst_ip)/UDP(dport=self.dns_port)/DNS(
            id=65534,  # Special sequence for sync
            qr=0,
            ra=0
        )
        super().send(sync_packet)
        #time.sleep(0.02)  # Wait for receiver to initialize
        
        checking_for_dot_character = ""
        i = 0
        
        try:
            while True:
                #if i % 10 == 0:
                #    print(f"Sending bit {i}")
                
                # Send bit using RA flags
                if binary_message[i] == '0':
                    self.send_dns_packet(ra_flag=0)
                    self.send_dns_packet(ra_flag=0)
                else:
                    self.send_dns_packet(ra_flag=0)
                    self.send_dns_packet(ra_flag=1)
                
                checking_for_dot_character += binary_message[i]
                if len(checking_for_dot_character) == 8:
                    if checking_for_dot_character == "00101110":
                        print("End of message detected")
                        end = time.time()
                        print(end-start)
                        break
                    checking_for_dot_character = ""
                
                i += 1
                if i >= len(binary_message):
                    break
                
        except KeyboardInterrupt:
            print("\nTransmission interrupted")
            raise

    def receive(self, log_file_name):
        print("Starting receiver...")
        decoded_message = ""
        checking_for_dot_character = ""
        received_message = ""
        expected_seq = 0
        packet_buffer = []
        in_sync = False
        
        def process_packet(packet):
            """Process received DNS packet"""
            nonlocal packet_buffer, in_sync, expected_seq
            
            if DNS not in packet:
                return
            
            # Handle sync packet
            if not in_sync and packet[DNS].id == 65534:
                print("Sync packet received")
                in_sync = True
                expected_seq = 0
                return
            
            if not in_sync:
                return
            
            # Add packet to buffer
            packet_buffer.append(packet)
            
            # Process pairs of packets
            if len(packet_buffer) >= 2:
                p1, p2 = packet_buffer[:2]
                packet_buffer = packet_buffer[2:]
                
                #print(f"Processing packets with seq {p1[DNS].id}, {p2[DNS].id}")
                return process_packet_pair(p1, p2)
            
            return False
            
        def process_packet_pair(p1, p2):
            """Process a pair of packets to decode a bit"""
            nonlocal decoded_message, checking_for_dot_character, received_message
            
            # Decode based on RA flags
            if p1[DNS].ra == p2[DNS].ra:
                decoded_message += '0'
                checking_for_dot_character += '0'
            else:
                decoded_message += '1'
                checking_for_dot_character += '1'
            
            #print(f"Decoded bits so far: {len(decoded_message)}")
            
            # Check for message end
            if len(checking_for_dot_character) == 8:
                try:
                    char = self.convert_eight_bits_to_character(checking_for_dot_character)
                    received_message += char
                    #print(f"Decoded character: {char}")
                    
                    if char == '.':
                        print("End of message detected")
                        self.log_message(received_message, log_file_name)
                        return True
                    checking_for_dot_character = ""
                except ValueError as e:
                    print(f"Error converting bits: {e}")
                    checking_for_dot_character = checking_for_dot_character[1:]
            
            return False
        
        try:
            print("Waiting for packets...")
            sniff(
                filter=f"udp and host {self.src_ip} and port {self.dns_port}",
                prn=process_packet,
                stop_filter=lambda p: DNS in p and len(received_message) > 0 and received_message[-1] == '.',
                store=0
            )
            
            print(f"\nFinal message: {received_message}")
            
        except KeyboardInterrupt:
            print("\nReceive interrupted")
            if received_message:
                self.log_message(received_message, log_file_name)