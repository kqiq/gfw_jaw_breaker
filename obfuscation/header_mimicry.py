"""
Protocol Header Mimicry module for GFW evasion.

This module adds protocol-specific headers to network traffic to make it appear
as legitimate HTTP or TLS traffic, helping to bypass the GFW's deep packet inspection.
"""
import random
import logging
import time
import socket
from typing import Dict, Any, List, Optional, Tuple, Union

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Common HTTP headers and values for mimicry
HTTP_METHODS = [b"GET ", b"POST ", b"HEAD "]
HTTP_VERSIONS = [b"HTTP/1.1", b"HTTP/1.0", b"HTTP/2.0"]
HTTP_PATHS = [
    b"/",
    b"/index.html",
    b"/api/v1/data",
    b"/assets/main.css",
    b"/images/logo.png",
    b"/js/main.js",
]
HTTP_HOSTS = [
    b"www.google.com",
    b"www.microsoft.com",
    b"www.github.com",
    b"www.apple.com",
    b"www.cloudflare.com",
]
HTTP_USER_AGENTS = [
    b"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    b"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    b"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
]
HTTP_ACCEPT = [
    b"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    b"application/json, text/plain, */*",
    b"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
]

# TLS version bytes (record version + handshake version)
TLS_VERSIONS = [
    (b"\x03\x01", b"\x03\x01"),  # TLS 1.0
    (b"\x03\x02", b"\x03\x02"),  # TLS 1.1
    (b"\x03\x03", b"\x03\x03"),  # TLS 1.2
    (b"\x03\x03", b"\x03\x04"),  # TLS 1.3 (uses 1.2 record version)
]

def generate_http_request_header() -> bytes:
    """
    Generate a realistic HTTP request header.
    
    Returns:
        Byte string containing a random HTTP request header
    """
    method = random.choice(HTTP_METHODS)
    path = random.choice(HTTP_PATHS)
    version = random.choice(HTTP_VERSIONS)
    host = random.choice(HTTP_HOSTS)
    user_agent = random.choice(HTTP_USER_AGENTS)
    accept = random.choice(HTTP_ACCEPT)
    
    # Current time in GMT format
    current_time = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())
    
    # Build the HTTP header
    header = (
        method + path + b" " + version + b"\r\n"
        b"Host: " + host + b"\r\n"
        b"User-Agent: " + user_agent + b"\r\n"
        b"Accept: " + accept + b"\r\n"
        b"Connection: keep-alive\r\n"
        b"Date: " + current_time.encode() + b"\r\n"
        b"\r\n"
    )
    
    return header

def generate_tls_client_hello() -> bytes:
    """
    Generate a realistic TLS Client Hello message.
    
    Returns:
        Byte string containing a TLS Client Hello
    """
    # Select TLS version
    record_version, handshake_version = random.choice(TLS_VERSIONS)
    
    # Generate random 32-byte client random (4 bytes timestamp + 28 bytes random)
    timestamp = int(time.time()).to_bytes(4, byteorder='big')
    random_bytes = bytes(random.getrandbits(8) for _ in range(28))
    client_random = timestamp + random_bytes
    
    # Generate random session ID (0-32 bytes)
    session_id_length = random.choice([0, 16, 32])
    session_id = bytes(random.getrandbits(8) for _ in range(session_id_length))
    
    # Common cipher suites (TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, etc.)
    cipher_suites = bytes([
        0x00, 0x06,  # Length of cipher suites (6 bytes = 3 cipher suites)
        0xc0, 0x2f,  # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        0xc0, 0x30,  # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        0x00, 0x9f,  # TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
    ])
    
    # Compression methods (null)
    compression_methods = bytes([0x01, 0x00])  # Length 1, null compression
    
    # Extensions length placeholder (will be calculated later)
    extensions_length_placeholder = bytes([0x00, 0x00])
    
    # Build the handshake message
    handshake_body = (
        handshake_version +  # Client version
        client_random +  # Client random
        bytes([session_id_length]) + session_id +  # Session ID
        cipher_suites +  # Cipher suites
        compression_methods +  # Compression methods
        extensions_length_placeholder  # Extensions length placeholder (we're not adding extensions in this simple example)
    )
    
    # Client Hello message type (1) and length
    handshake_header = bytes([0x01]) + len(handshake_body).to_bytes(3, byteorder='big')
    
    # Complete handshake message
    handshake_message = handshake_header + handshake_body
    
    # TLS record header
    record_header = (
        b"\x16" +  # Content type: Handshake (22)
        record_version +  # Protocol version
        len(handshake_message).to_bytes(2, byteorder='big')  # Length
    )
    
    # Complete TLS record
    return record_header + handshake_message

def apply_protocol_header(packet: bytes, protocol_type: str = "tls") -> bytes:
    """
    Apply protocol-specific header to a packet.
    
    Args:
        packet: The packet data to modify
        protocol_type: Type of protocol mimicry to apply ("http", "tls", or "random")
        
    Returns:
        Modified packet with protocol header
    """
    if protocol_type == "random":
        protocol_type = random.choice(["http", "tls"])
    
    if protocol_type == "http":
        header = generate_http_request_header()
    elif protocol_type == "tls":
        header = generate_tls_client_hello()
    else:
        logger.warning(f"Unknown protocol type: {protocol_type}, using TLS")
        header = generate_tls_client_hello()
    
    logger.debug(f"Applied {protocol_type} header mimicry, added {len(header)} bytes")
    return header + packet

class HeaderMimicry:
    """
    Applies protocol header mimicry to network traffic.
    """
    
    def __init__(self, default_protocol: str = "tls"):
        """
        Initialize the HeaderMimicry object.
        
        Args:
            default_protocol: Default protocol to mimic ("http", "tls", or "random")
        """
        self.default_protocol = default_protocol
        self.connection_protocols = {}
        self.connection_first_packets = set()
    
    def process_packet(self, packet: bytes, connection_id: str = None, protocol_type: str = None) -> bytes:
        """
        Process a packet, applying protocol header mimicry if it's the first in a connection.
        
        Args:
            packet: The packet data to process
            connection_id: Unique identifier for the connection (if available)
            protocol_type: Type of protocol to mimic (overrides default)
            
        Returns:
            Processed packet data
        """
        # Determine which protocol to use
        if not protocol_type:
            protocol_type = self.default_protocol
        
        # If no connection ID, assume it could be a first packet
        if not connection_id:
            return apply_protocol_header(packet, protocol_type)
        
        # Check if this is the first packet of this connection
        if connection_id not in self.connection_first_packets:
            self.connection_first_packets.add(connection_id)
            
            # Store which protocol was used for this connection
            self.connection_protocols[connection_id] = protocol_type
            
            # Apply the protocol header
            return apply_protocol_header(packet, protocol_type)
            
        # Not the first packet
        return packet 