from CovertChannelBase import CovertChannelBase
from scapy.all import IP, UDP, DNS, DNSQR, sniff
import time

class MyCovertChannel(CovertChannelBase):
    def __init__(self):
        super().__init__()
        self.dst_ip = "172.18.0.3"
        self.src_ip = "172.18.0.2"
        self.dns_port = 53
        self.current_seq = 0
        
        # Key for XOR operation
        self.xor_key = 0b1011
        
        # Adjusted delays with smaller values
        self.default_delays = {
            'reliable': 0.002,  # 2ms
            'fast': None,      
            'stealth': 0.01     # 10ms
        }

    def preprocess_bits(self, bits, chunk_size):
        """
        Preprocess bits using bitwise operations:
        1. Group bits into chunks
        2. XOR with key
        3. Rotate left by 1
        """
        while len(bits) % chunk_size != 0:
            bits += '0'
            
        processed_bits = ''
        for i in range(0, len(bits), chunk_size):
            chunk = bits[i:i+chunk_size]
            chunk_val = int(chunk, 2)
            
            # XOR with key
            xored = chunk_val ^ self.xor_key
            
            # Rotate left by 1
            rotated = ((xored << 1) | (xored >> (chunk_size-1))) & ((1 << chunk_size) - 1)
            
            processed_chunk = format(rotated, f'0{chunk_size}b')
            processed_bits += processed_chunk
            
        return processed_bits

    def reverse_preprocessing(self, processed_bits, chunk_size):
        """
        Reverse the preprocessing:
        1. Group bits into chunks
        2. Rotate right by 1
        3. XOR with key
        """
        original_bits = ''
        for i in range(0, len(processed_bits), chunk_size):
            chunk = processed_bits[i:i+chunk_size]
            chunk_val = int(chunk, 2)
            
            # Rotate right by 1
            rotated = ((chunk_val >> 1) | (chunk_val << (chunk_size-1))) & ((1 << chunk_size) - 1)
            
            # XOR with key
            original = rotated ^ self.xor_key
            
            original_chunk = format(original, f'0{chunk_size}b')
            original_bits += original_chunk
            
        return original_bits

    def send_dns_packet(self, ra_flag, delay=None):
        """Send DNS packet with more consistent timing"""
        start_time = time.time()
        
        dns_query = IP(dst=self.dst_ip) / UDP(dport=self.dns_port) / DNS(
            id=self.current_seq,
            qr=0,
            ra=ra_flag
        )
        super().send(dns_query)
        self.current_seq = (self.current_seq + 1) % 65535
        
        if delay is not None:
            elapsed = time.time() - start_time
            remaining = delay - elapsed
            if remaining > 0:
                time.sleep(remaining)

    def decode_binary_to_message(self, binary_message):
        message = ""
        current_bits = ""
        
        for bit in binary_message:
            current_bits += bit
            if len(current_bits) == 8:
                try:
                    char = self.convert_eight_bits_to_character(current_bits)
                    message += char
                    if char == '.':
                        return message
                    current_bits = ""
                except ValueError as e:
                    current_bits = current_bits[1:]
        return message

    def send(self, log_file_name, transmission_mode='fast', chunk_size=8, validation_mode='xor'):
        """
        Sends a covert message by manipulating DNS RA flag.
        
        Flow:
        1. Generate random binary message and log it
        2. Preprocess binary message using XOR and rotation operations
        3. Add validation bits to each chunk based on validation mode
        4. Send each bit through DNS packets by setting RA flag
        5. Send final packet to signal transmission end
        
        Args:
            log_file_name (str): File to log the original message
            transmission_mode (str): Speed of transmission ('fast', 'reliable', 'stealth')
            chunk_size (int): Size of chunks for preprocessing (4-8 bits) (give this parameter as 4 or 8, the most optimized one is 8)
            validation_mode (str): Type of validation ('xor', 'parity', 'pattern')
        
    """
        start = time.time()
        binary_message = self.generate_random_binary_message_with_logging(log_file_name)

        # First preprocess with bitwise operations
        processed_message = self.preprocess_bits(binary_message, chunk_size)
        
        # Then apply validation bits based on validation_mode
        final_message = ''
        for i in range(0, len(processed_message), chunk_size):
            chunk = processed_message[i:i+chunk_size]
            if len(chunk) == chunk_size:
                if validation_mode == 'xor':
                    xor_result = 0
                    for bit in chunk:
                        xor_result ^= int(bit)
                    chunk += str(xor_result ^ 1)
                elif validation_mode == 'parity':
                    ones_count = sum(int(bit) for bit in chunk)
                    chunk += '1' if ones_count % 2 == 0 else '0'
                elif validation_mode == 'pattern':
                    chunk += '1' if chunk[-1] == '0' else '0'
            final_message += chunk

        delay = self.default_delays[transmission_mode]

        try:
            for bit in final_message:
                self.send_dns_packet(int(bit), delay)
            
            final_packet = IP(dst=self.dst_ip) / UDP(dport=self.dns_port) / DNS(
                id=65535,
                qr=0,
                ra=0
            )
            super().send(final_packet)

            end = time.time()
            actual_time = end - start
            print("message transmission time: ", actual_time, " seconds")
            print("channel capacity (bits/sec): ", len(binary_message)/actual_time, " bits/sec")
        except KeyboardInterrupt:
            print("\nTransmission interrupted")
            raise

    def validate_chunk(self, chunk, validation_mode):
        """Validate chunk based on selected mode"""
        if validation_mode == 'xor':
            xor_result = 0
            for bit in chunk:
                xor_result ^= int(bit)
            return xor_result == 1
        elif validation_mode == 'parity':
            return sum(int(bit) for bit in chunk) % 2 == 1
        elif validation_mode == 'pattern':
            return not all(chunk[i] == chunk[i-1] for i in range(1, len(chunk)))
        return True

    def receive(self, log_file_name, chunk_size=8, validation_mode='xor'):
        """
        Receives and decodes covert messages from DNS RA flags.
        
        Flow:
        1. Sniff DNS packets and extract RA flag values
        2. Accumulate bits until a full chunk is received
        3. Validate each chunk using specified validation mode
        4. Process valid chunks through reverse preprocessing
        5. Accumulate original bits and try to decode message
        6. Stop when complete message (ending with '.') is received
        
        Args:
            log_file_name (str): File to save the decoded message
            chunk_size (int): Size of chunks for preprocessing (4-8 bits) (give this parameter as 4 or 8, the most optimized one is 8)
            validation_mode (str): Type of validation ('xor', 'parity', 'pattern')
        
        Implementation details:
        - Uses nested process_packet function for packet handling
        - Maintains running counters for processed and valid chunks
        - Accumulates bits until valid message is found
        - Stops on final packet (ID 65535) after message is decoded
        """
        received_bits = []
        accumulated_bits = []
        final_message = None
        processed_chunks = 0
        valid_chunks = 0
        validation_chunk_size = chunk_size + 1  # Include validation bit

        def process_packet(packet):
            nonlocal received_bits, accumulated_bits, final_message, processed_chunks, valid_chunks

            if DNS not in packet:
                return False

            if packet[DNS].id == 65535 and final_message is not None:
                self.log_message(final_message, log_file_name)
                return True

            received_bits.append(str(packet[DNS].ra))

            if len(received_bits) >= validation_chunk_size:
                processed_chunks += 1
                full_chunk = received_bits[:validation_chunk_size]
                data_bits = full_chunk[:-1]  # First chunk_size bits are data

                if not self.validate_chunk(full_chunk, validation_mode):
                    received_bits = received_bits[validation_chunk_size:]
                    return False

                valid_chunks += 1

                try:
                    # Process only the data bits (without validation bit)
                    processed_bits = ''.join(data_bits)
                    original_bits = self.reverse_preprocessing(processed_bits, chunk_size)
                    accumulated_bits.extend(original_bits)
                    
                    # Try to decode the entire accumulated message
                    binary_message = ''.join(accumulated_bits)
                    decoded_message = self.decode_binary_to_message(binary_message)
                    
                    if decoded_message and decoded_message[-1] == '.':
                        final_message = decoded_message
                        return False

                except Exception as e:
                    print(f"Error processing chunk: {e}")

                received_bits = received_bits[validation_chunk_size:]

            return False

        try:
            sniff(
                filter=f"udp and host {self.src_ip} and port {self.dns_port}",
                prn=lambda pkt: process_packet(pkt) or None,
                stop_filter=lambda p: DNS in p and p[DNS].id == 65535 and final_message is not None,
                store=0
            )

        except KeyboardInterrupt:
            print("\nReceive interrupted")
            if final_message:
                self.log_message(final_message, log_file_name)
