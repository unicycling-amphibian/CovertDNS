import argparse
import socket
import struct
import codecs
import dns.resolver
import dns.message
import dns.query
import base64
from aes import aes

# Address of the DNS server
#dns_server = "8.8.8.8"

# DNS query message format
#dns_query = struct.pack("!6H", 0x1234, 1, 1, 0, 0, 0) + b"\x03foo\x03bar\x00\x00\x01\x00\x01"


def encrypt_message(message, key):
    # Pad the message to a multiple of 16 bytes
    message = message + b' ' * (16 - len(message) % 16)

    # Create an AES cipher object and encrypt the message
    cipher = aes.new(key, aes.MODE_ECB)
    encrypted_message = cipher.encrypt(message)

    # Return the base64 encoded encrypted message
    return base64.b64encode(encrypted_message).decode()

def encode_message(message, key):
    # Encrypt the message using AES encryption
    encrypted_message = encrypt_message(message.encode(), key)

    # Convert the encrypted message into the format described in the specifications
    encoded_message = ''
    for char in encrypted_message:
        encoded_message += str(ord(char) * 2) + '.'

    # Return the encoded message
    return encoded_message.rstrip('.')

#def encode_message(message):
#    # Map of characters to binary
#    mapping = {chr(97 + i): format(i, '05b') for i in range(26)}
#    mapping['EOF'] = '11111'
#
#    # Encode message as binary
#    message = ''.join(mapping[c] for c in message)
#
#    # Split message into 10-bit chunks
#    message = [message[i:i + 10] for i in range(0, len(message), 10)]
#
#    # Convert 10-bit chunks to integer values
#    message = [int(chunk, 2) for chunk in message]
#
#    return message
#

def decode_message(encoded_message):
    # Split the encoded message into individual values
    values = encoded_message.split('.')

    # Convert the values back into characters
    decoded_message = ''
    for value in values:
        decoded_message += chr(int(value) // 2)

    # Decrypt the message using AES encryption
    decrypted_message = decrypt_message(decoded_message.encode(), key)

    # Return the decrypted message
    return decrypted_message.rstrip()

def decrypt_message(encrypted_message, key):
    # Decode the base64 encoded encrypted message
    encrypted_message = base64.b64decode(encrypted_message)

    # Create an AES cipher object and decrypt the message
    cipher = aes.new(key, aes.MODE_ECB)
    decrypted_message = cipher.decrypt(encrypted_message)

    # Return the decrypted message
    return decrypted_message.rstrip()

def send_payload_to_target(message, domain, source):
    mapping = {'00000': 'a', '00001': 'b', '00010': 'c', '00011': 'd',
               '00100': 'e', '00101': 'f', '00110': 'g', '00111': 'h',
               '01000': 'i', '01001': 'j', '01010': 'k', '01011': 'l',
               '01100': 'm', '01101': 'n', '01110': 'o', '01111': 'p',
               '10000': 'q', '10001': 'r', '10010': 's', '10011': 't',
               '10100': 'u', '10101': 'v', '10110': 'w', '10111': 'x',
               '11000': 'y', '11001': 'z', '11011': '0', '11100': '1',
               '11101': '2', '11110': '3', '11111': '4'}

    # Check if message is a string
    if not isinstance(message, str):
        raise ValueError("Message must be a string")

    # Check if message contains only lowercase letters and numbers
    for char in message:
        if char not in mapping.values():
            raise ValueError("Message must contain only lowercase letters and numbers")

    # Convert message to binary
    message = ''.join(format(ord(char) - ord('a'), '05b') for char in message)

    # Pad message with EOF character to make its length a multiple of 10
    message += '11011' * (10 - len(message) % 10)

    # Multiply binary values by 5 to obtain larger TTL values
    message = ''.join(format(int(char, 2) * 5, '05b') for char in message)

    # Split data into 10-bit chunks
    chunks = [message[i:i+10] for i in range(0, len(message), 10)]

    # Convert 10-bit chunks to integer values
    chunks = [int(chunk, 2) for chunk in chunks]

    # Send DNS requests with TTL values
    for chunk in chunks:
        request = dns.message.make_query(domain, dns.rdatatype.A)
        response = dns.query.udp(request, source, timeout=1)
        if response.rcode() != dns.rcode.NOERROR:
            raise Exception("DNS query failed")

        ttl = response.answer[0].ttl
        if ttl != chunk:
            raise Exception("Unexpected TTL value")

    return True


# Function to decode the covert message from the DNS reply
#def decode_message(data):
#    # Map of binary to characters
#    mapping = {format(i, '05b'): chr(97 + i) for i in range(26)}
#    mapping['11111'] = 'EOF'
#
#    # Split data into 10-bit chunks
#    chunks = [data[i:i + 10] for i in range(0, len(data), 10)]
#
#    # Convert 10-bit chunks to integer values
#    chunks = [int(chunk, 2) for chunk in chunks]
#
#    # Divide integer values by 5 to obtain original message
#    chunks = [chunk // 5 for chunk in chunks]
#
#    # Convert integer values to binary
#    chunks = [format(chunk, '05b') for chunk in chunks]
#
#    # Join binary values to form the message
#    message = ''.join(chunks)
#
#    # Split message into character codes
#    message = [message[i:i + 5] for i in range(0, len(message), 5)]
#
#    # Convert character codes to characters
#    message = ''.join(mapping[code] for code in message)
#
#    return message

def dns_spoof(target, source_ip, source_port, payload, aes_key=None):
    try:
        # Encode the message using the text only scheme
        encoded_message = ''
        for char in payload:
            encoded_message += str((ord(char) - 97) * 26 ** 2)

        # AES encryption implementation here
        encrypted_message = encrypt_message(aes_key, encoded_message) if aes_key else encoded_message

        # Construct the DNS packet
        packet = b''
        packet += struct.pack("!H", 0x1234) # Transaction ID
        packet += struct.pack("!H", 0x0100) # Flags
        packet += struct.pack("!H", 1) # Questions
        packet += struct.pack("!H", 0) # Answer RRs
        packet += struct.pack("!H", 0) # Authority RRs
        packet += struct.pack("!H", 0) # Additional RRs
        packet += b'\x03\x77\x77\x77\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00' # Domain name
        packet += struct.pack("!H", 0x0001) # Query type
        packet += struct.pack("!H", 0x0001) # Query class

        # Split the message into 4 character segments
        message_segments = [encrypted_message[i:i+4] for i in range(0, len(encrypted_message), 4)]
        # Encode the message segments into TTL values
        ttl_values = []
        for segment in message_segments:
            ttl = 0
            for char in segment:
                ttl = ttl * 26 + ord(char) - 97
            ttl_values.append(ttl * 5)

        # Add the TTL values to the packet as answers
        for ttl in ttl_values:
            packet += b'\xc0\x0c' # Pointer to domain name
            packet += struct.pack("!H", 0x0001) # Query type
            packet += struct.pack("!H", 0x0001) # Query class
            packet += struct.pack("!I", ttl) # TTL

        # Create a raw socket
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        # Set the source IP and source port for spoofing
        s.bind((source_ip, source_port))
        # Send the packet
        s.sendto(packet, (target, 53))

        # Passive listening for a reply
        response, addr = s.recvfrom(1024)
        # Verify that the reply is from the expected target
        if addr[0] == target:
            # Extract the TTL values from the response
            ttl_values = []
            for i in range(len(response)):
                if response[i:i+2] == b'\x00\x01':
                    ttl = struct.unpack("!I", response[i+10:i+14])[0]
    except socket.error as e:
        print(f"Error: {e}")
    finally:
        s.close()

def parse_arguments():
    parser = argparse.ArgumentParser(description='Send payload over a covert DNS channel.')
    parser.add_argument('payload', type=str, help='The message to send.')
    parser.add_argument('target', type=str, help='The target to send the message to.')
    parser.add_argument('source', type=str, help='The true client to receive the message')
    parser.add_argument('-s', '--spoof', dest='spoof', action='store_true', help='Spoof the source address on the request.')
    parser.add_argument('--key', type=str, default='1234567890abcdef', help='Encryption key')
    return parser.parse_args()

#python covert_channel_client.py <payload> <target> [--key <key>]
if __name__ == '__main__':
    args = parse_arguments()
    payload = args.payload
    target = args.target
    source = args.source
    key = args.key
    spoof = args.spoof

    if spoof:
        print("Spoofing address on request...")
        dns_spoof(target, spoof, 53, payload, key)

    # Encode the payload
    encoded_payload = encode_message(payload, key)

    # Send the encoded payload to the target domain
    send_payload_to_target(encoded_payload, target, source)
