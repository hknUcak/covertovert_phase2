# Covert Storage Channel that exploits Protocol Field Manipulation using RA Flag field in DNS

This project implements a covert storage channel using DNS protocol's RA (Recursion Available) flag. It demonstrates how protocol field manipulation can be used to create hidden communication channels within legitimate network traffic.

## Overview

A covert channel is a communication channel that transfers information in a way that was not designed or intended to transfer information at all. This implementation specifically uses the DNS protocol's RA flag as a storage channel to transmit hidden messages.

### Key Features

- **Protocol Field Manipulation**: Exploits DNS RA flag for covert communication
- **Bitwise Preprocessing**: Applies XOR and rotation operations for enhanced security
- **Validation Modes**: Multiple validation schemes for data integrity
- **Sophisticated Encoding**: Uses chunk-based processing with validation bits

## Technical Details

### Covert Channel Implementation

The covert channel works by:
1. Converting the secret message to binary
2. Preprocessing the binary data using bitwise operations
3. Adding validation bits for error detection
4. Transmitting the data by manipulating the RA flag in DNS packets

### Components

#### Sender
The sender component handles message preprocessing and transmission:
```python
send("message.log", transmission_mode='reliable', chunk_size=8, validation_mode='xor')
```
- Converts message to binary
- Applies preprocessing (XOR and rotation)
- Adds validation bits
- Transmits via DNS RA flag
chunk_size minimum value = 2, max value = 8
validation_mode can take 'xor', 'parity', 'pattern'

#### Receiver
The receiver component captures and processes DNS packets:
```python
receive("received.log", chunk_size=8, validation_mode='xor')
```
- Captures DNS packets
- Extracts RA flag values
- Validates and processes chunks
- Reconstructs original message
chunk_size minimum value = 2, max value = 8
validation_mode can take 'xor', 'parity', 'pattern'

### Preprocessing

The implementation uses sophisticated preprocessing to make the covert channel harder to detect:

```python
def preprocess_bits(self, bits, chunk_size):
    # Group bits into chunks
    # XOR with key
    xored = chunk_val ^ self.xor_key
    # Rotate left by 1
    rotated = ((xored << 1) | (xored >> (chunk_size-1))) & ((1 << chunk_size) - 1)
```

## Usage

### Prerequisites
- Python 3.10.12
- Scapy library

#### Transmission Modes
- `reliable`: 2ms delay (balanced)
- `fast`: no delay (maximum speed)
- `stealth`: 10ms delay (harder to detect)

#### Validation Modes
- `xor`: XOR-based validation
- `parity`: Parity bit checking
- `pattern`: Pattern-based validation

#### Other Parameters
- `chunk_size`: Size of processing chunks (default: 8)

## Technical Implementation

### DNS Packet Structure
```python
dns_query = IP(dst=self.dst_ip) / UDP(dport=self.dns_port) / DNS(
    id=self.current_seq,
    qr=0,
    ra=ra_flag  # Covert data carried in RA flag
)
```

### Message Flow
1. Original Message → Binary
2. Binary → Preprocessing
3. Add Validation Bits
4. Transmit via RA Flag
5. Receive and Validate
6. Reverse Preprocessing
7. Reconstruct Message

### Covert Channel Capacity in Bits Per Second
17.68

## References

- DNS Protocol Specification (RFC 1035)
- Covert Channel Techniques in Computer Networks
- Network Protocol Analysis and Security
