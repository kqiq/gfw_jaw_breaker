"""
Obfuscation protocols to bypass deep packet inspection.
"""
import asyncio
import base64
import random
import string
import ssl
import websockets
import logging
from typing import Dict, Any, Callable, Optional, Tuple, List

from config.config import LOG_LEVEL

# Configure logging
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ObfuscationProtocol:
    """Base class for obfuscation protocols."""
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize the obfuscation protocol.
        
        Args:
            config: Dictionary of configuration options
        """
        self.config = config or {}
        self.name = "base"
    
    async def obfuscate(self, data: bytes) -> bytes:
        """
        Obfuscate the data to bypass deep packet inspection.
        
        Args:
            data: Raw data to obfuscate
            
        Returns:
            Obfuscated data
        """
        # Base implementation just passes through
        return data
    
    async def deobfuscate(self, data: bytes) -> bytes:
        """
        Deobfuscate the data back to its original form.
        
        Args:
            data: Obfuscated data
            
        Returns:
            Original data
        """
        # Base implementation just passes through
        return data

class TLSObfuscation(ObfuscationProtocol):
    """TLS-based obfuscation that makes traffic look like HTTPS."""
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.name = "tls"
        self.tls_header = b'\x16\x03\x01'  # TLS handshake
        self.tls_version = b'\x03\x03'     # TLS 1.2
        
    async def obfuscate(self, data: bytes) -> bytes:
        """
        Wrap data in TLS-like framing.
        
        This doesn't implement actual TLS, but makes traffic look like TLS
        to evade simple pattern matching filters.
        """
        # Add TLS-like header
        length = len(data)
        length_bytes = length.to_bytes(2, byteorder='big')
        
        # TLS Record: ContentType(1) + Version(2) + Length(2) + Data
        tls_record = self.tls_header + length_bytes + data
        
        # Add some random padding to vary packet sizes
        padding_length = random.randint(0, 32)
        padding = bytes([random.randint(0, 255) for _ in range(padding_length)])
        
        return tls_record + padding
    
    async def deobfuscate(self, data: bytes) -> bytes:
        """Extract the original data from TLS-like framing."""
        # Skip TLS header (3 bytes) and length (2 bytes)
        return data[5:]

class HTTPObfuscation(ObfuscationProtocol):
    """HTTP-based obfuscation that makes traffic look like normal web requests."""
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.name = "http"
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko)",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15",
            "Mozilla/5.0 (iPad; CPU OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15"
        ]
        
    async def obfuscate(self, data: bytes) -> bytes:
        """Wrap data in HTTP-like request."""
        # Base64 encode the data
        encoded_data = base64.b64encode(data).decode('utf-8')
        
        # Generate random HTTP headers
        user_agent = random.choice(self.user_agents)
        headers = [
            f"User-Agent: {user_agent}",
            f"Content-Length: {len(encoded_data)}",
            "Accept: text/html,application/xhtml+xml,application/xml",
            "Accept-Language: en-US,en;q=0.9",
            f"X-Request-ID: {self._generate_request_id()}",
            f"Cookie: session={self._generate_random_string(32)}"
        ]
        
        # Randomize header order
        random.shuffle(headers)
        headers_str = "\r\n".join(headers)
        
        # Create HTTP request
        request = (
            f"POST /api/data HTTP/1.1\r\n"
            f"Host: {self._generate_random_domain()}\r\n"
            f"{headers_str}\r\n"
            f"\r\n"
            f"{encoded_data}"
        )
        
        return request.encode('utf-8')
    
    async def deobfuscate(self, data: bytes) -> bytes:
        """Extract the original data from HTTP-like request."""
        try:
            # Convert to string
            data_str = data.decode('utf-8')
            
            # Find the double newline separating headers from body
            body_start = data_str.find('\r\n\r\n') + 4
            
            if body_start > 3:
                # Extract the body
                body = data_str[body_start:]
                
                # Decode base64
                return base64.b64decode(body)
            else:
                # Fallback if we can't find the expected format
                logger.warning("HTTP deobfuscation format error, falling back to raw data")
                return data
        except Exception as e:
            logger.error(f"HTTP deobfuscation error: {str(e)}")
            # Return original data on error
            return data
    
    def _generate_random_domain(self) -> str:
        """Generate a random-looking domain name."""
        tlds = ['.com', '.org', '.net', '.io', '.co']
        domain = self._generate_random_string(random.randint(5, 10))
        return domain + random.choice(tlds)
    
    def _generate_random_string(self, length: int) -> str:
        """Generate a random string of specified length."""
        chars = string.ascii_lowercase + string.digits
        return ''.join(random.choice(chars) for _ in range(length))
    
    def _generate_request_id(self) -> str:
        """Generate a UUID-like request ID."""
        hex_chars = string.hexdigits.lower()[:16]
        parts = [
            ''.join(random.choice(hex_chars) for _ in range(8)),
            ''.join(random.choice(hex_chars) for _ in range(4)),
            ''.join(random.choice(hex_chars) for _ in range(4)),
            ''.join(random.choice(hex_chars) for _ in range(4)),
            ''.join(random.choice(hex_chars) for _ in range(12))
        ]
        return '-'.join(parts)

class WebSocketObfuscation(ObfuscationProtocol):
    """WebSocket-based obfuscation that makes traffic look like WebSocket connections."""
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.name = "websocket"
        
    async def obfuscate(self, data: bytes) -> bytes:
        """
        WebSocket frame format (simplified):
        
        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-------+-+-------------+-------------------------------+
        |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
        |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
        |N|V|V|V|       |S|             |   (if payload len==126/127)   |
        | |1|2|3|       |K|             |                               |
        +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
        |     Extended payload length continued, if payload len == 127  |
        + - - - - - - - - - - - - - - - +-------------------------------+
        |                               |Masking-key, if MASK set to 1  |
        +-------------------------------+-------------------------------+
        | Masking-key (continued)       |          Payload Data         |
        +-------------------------------- - - - - - - - - - - - - - - - +
        :                     Payload Data continued ...                :
        + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
        |                     Payload Data continued ...                |
        +---------------------------------------------------------------+
        """
        fin = 1  # Final fragment
        opcode = 2  # Binary frame
        mask = 1  # Client to server should be masked
        header = (fin << 7) | opcode
        
        length = len(data)
        if length < 126:
            length_bytes = bytes([mask << 7 | length])
            extended_length = b''
        elif length < 65536:
            length_bytes = bytes([mask << 7 | 126])
            extended_length = length.to_bytes(2, byteorder='big')
        else:
            length_bytes = bytes([mask << 7 | 127])
            extended_length = length.to_bytes(8, byteorder='big')
        
        # Generate masking key (4 bytes)
        masking_key = bytes([random.randint(0, 255) for _ in range(4)])
        
        # Apply masking key to data
        masked_data = bytearray(data)
        for i in range(len(masked_data)):
            masked_data[i] ^= masking_key[i % 4]
        
        # Assemble WebSocket frame
        frame = bytes([header]) + length_bytes + extended_length + masking_key + bytes(masked_data)
        
        return frame
    
    async def deobfuscate(self, data: bytes) -> bytes:
        """Extract the original data from WebSocket frame."""
        try:
            i = 0
            
            # Parse header
            header = data[i]
            i += 1
            
            # Parse length
            mask_and_length = data[i]
            i += 1
            
            masked = (mask_and_length & 0x80) != 0
            length = mask_and_length & 0x7F
            
            # Handle extended length
            if length == 126:
                length = int.from_bytes(data[i:i+2], byteorder='big')
                i += 2
            elif length == 127:
                length = int.from_bytes(data[i:i+8], byteorder='big')
                i += 8
            
            # Get masking key if masked
            masking_key = b''
            if masked:
                masking_key = data[i:i+4]
                i += 4
            
            # Get payload
            payload = data[i:i+length]
            
            # Unmask if necessary
            if masked:
                unmasked_payload = bytearray(payload)
                for j in range(len(unmasked_payload)):
                    unmasked_payload[j] ^= masking_key[j % 4]
                return bytes(unmasked_payload)
            else:
                return payload
            
        except Exception as e:
            logger.error(f"WebSocket deobfuscation error: {str(e)}")
            # Return original data on error
            return data

class RandomPaddingObfuscation(ObfuscationProtocol):
    """Adds random padding to data to confuse traffic analysis."""
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.name = "random_padding"
    
    async def obfuscate(self, data: bytes) -> bytes:
        """Add random padding before and after data."""
        # Add padding length markers and random padding
        prefix_length = random.randint(10, 100)
        suffix_length = random.randint(10, 100)
        
        # Create random padding
        prefix = bytes([random.randint(0, 255) for _ in range(prefix_length)])
        suffix = bytes([random.randint(0, 255) for _ in range(suffix_length)])
        
        # Format: 
        # [prefix length (2 bytes)][suffix length (2 bytes)][prefix][data][suffix]
        result = (
            prefix_length.to_bytes(2, byteorder='big') + 
            suffix_length.to_bytes(2, byteorder='big') + 
            prefix + 
            data + 
            suffix
        )
        
        return result
    
    async def deobfuscate(self, data: bytes) -> bytes:
        """Remove random padding from data."""
        try:
            # Extract padding lengths from header
            prefix_length = int.from_bytes(data[0:2], byteorder='big')
            suffix_length = int.from_bytes(data[2:4], byteorder='big')
            
            # Extract data
            data_start = 4 + prefix_length
            data_end = len(data) - suffix_length
            
            return data[data_start:data_end]
        except Exception as e:
            logger.error(f"Random padding deobfuscation error: {str(e)}")
            # Return original data on error
            return data

# Factory function to create the appropriate obfuscation protocol
def create_obfuscation_protocol(name: str, config: Dict[str, Any] = None) -> ObfuscationProtocol:
    """
    Create an obfuscation protocol by name.
    
    Args:
        name: Name of the obfuscation protocol
        config: Optional configuration for the protocol
        
    Returns:
        Instantiated obfuscation protocol
    """
    protocols = {
        "tls": TLSObfuscation,
        "http": HTTPObfuscation,
        "websocket": WebSocketObfuscation,
        "random_padding": RandomPaddingObfuscation
    }
    
    if name in protocols:
        return protocols[name](config)
    else:
        logger.warning(f"Unknown obfuscation protocol '{name}', using base protocol")
        return ObfuscationProtocol(config) 