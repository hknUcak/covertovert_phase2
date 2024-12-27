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
        """Send DNS packet with RA flag"""
        dns_query = IP(dst=self.dst_ip) / UDP(dport=self.dns_port) / DNS(
            id=self.current_seq,
            qr=0,
            ra=ra_flag
        )
        super().send(dns_query)
        self.current_seq = (self.current_seq + 1) % 65535
        time.sleep(0.005)

    def rle_encode(self, data):
        """Run-Length Encode a binary string."""
        encoded = []
        count = 1
        for i in range(1, len(data)):
            if data[i] == data[i - 1]:
                count += 1
            else:
                encoded.append((data[i - 1], count))
                count = 1
        encoded.append((data[-1], count))
        return encoded

    def rle_decode(self, encoded):
        """Decode an RLE encoded message."""
        decoded = ''.join(bit * count for bit, count in encoded)
        return decoded

    def decode_binary_to_message(self, binary_message):
        """Convert binary string to text message"""
        message = ""
        current_bits = ""
        
        for bit in binary_message:
            current_bits += bit
            if len(current_bits) == 8:
                try:
                    char = self.convert_eight_bits_to_character(current_bits)
                    message += char
                    if char == '.':
                        break
                    current_bits = ""
                except ValueError as e:
                    print(f"Error converting bits {current_bits}: {e}")
                    current_bits = current_bits[1:]
        
        return message

    def send(self, log_file_name):
        start = time.time()
        binary_message = self.generate_random_binary_message_with_logging(log_file_name)
        print(f"Original message length: {len(binary_message)} bits")

        # Preprocess the binary message with RLE
        rle_encoded_message = self.rle_encode(binary_message)
        print(f"RLE Encoded Message: {rle_encoded_message}")

        # Send initial sync packet
        sync_packet = IP(dst=self.dst_ip) / UDP(dport=self.dns_port) / DNS(
            id=65534,
            qr=0,
            ra=0
        )
        super().send(sync_packet)
        time.sleep(0.1)

        try:
            for bit, count in rle_encoded_message:
                print(f"Sending bit {bit} repeated {count} times")
                for _ in range(count):
                    self.send_dns_packet(ra_flag=int(bit))

            # Send end marker and stop
            print("Sending end marker")
            self.send_dns_packet(ra_flag=1)
            self.send_dns_packet(ra_flag=1)
            
            # Add a final confirmation packet
            final_packet = IP(dst=self.dst_ip) / UDP(dport=self.dns_port) / DNS(
                id=65535,  # Special ID for final packet
                qr=0,
                ra=0
            )
            super().send(final_packet)

            end = time.time()
            print(f"Transmission completed in {end - start:.2f} seconds")
            return  # Exit after sending final packet

        except KeyboardInterrupt:
            print("\nTransmission interrupted")
            raise

    def receive(self, log_file_name):
        print("Starting receiver...")
        rle_data = []
        last_bit = None
        bit_count = 0
        in_sync = False
        final_message = None

        def process_packet(packet):
            nonlocal in_sync, rle_data, last_bit, bit_count, final_message

            if DNS not in packet:
                return False

            # Handle sync packet
            if not in_sync and packet[DNS].id == 65534:
                print("Sync packet received")
                in_sync = True
                return False

            # Handle final packet - only stop if we have processed the message
            if packet[DNS].id == 65535 and final_message is not None:
                print("Final packet received")
                self.log_message(final_message, log_file_name)  # Log message here
                return True

            if not in_sync:
                return False

            # Process RA flag
            current_bit = str(packet[DNS].ra)
            
            if last_bit is None:
                last_bit = current_bit
                bit_count = 1
                return False

            if current_bit == last_bit:
                bit_count += 1
            else:
                rle_data.append((last_bit, bit_count))
                last_bit = current_bit
                bit_count = 1

            # Check for end marker (two consecutive 1s)
            if len(rle_data) > 0 and last_bit == '1' and bit_count >= 2:
                print("End marker detected")
                binary_message = self.rle_decode(rle_data)
                decoded_message = self.decode_binary_to_message(binary_message)
                print(f"Decoded message: {decoded_message}")
                final_message = decoded_message  # Store message but don't log yet
                return False

            return False

        try:
            print("Waiting for packets...")
            sniff(
                filter=f"udp and host {self.src_ip} and port {self.dns_port}",
                prn=process_packet,
                stop_filter=lambda p: DNS in p and p[DNS].id == 65535 and final_message is not None,
                store=0
            )

            if final_message:
                print(f"\nFinal message: {final_message}")
            else:
                print("No message received")

        except KeyboardInterrupt:
            print("\nReceive interrupted")
            if final_message:
                self.log_message(final_message, log_file_name)