"""
VMess protocol implementation for V2Ray.

VMess is a protocol used by V2Ray that adds a layer of encryption and obfuscation.
It's particularly effective against deep packet inspection.
"""
import asyncio
import logging
import random
import socket
import struct
import time
import uuid
import hashlib
import hmac
from typing import Dict, Any, Optional, Tuple, List, Union, Set

from utils.encryption import encrypt_data, decrypt_data
from config.config import LOG_LEVEL

# Configure logging
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# VMess constants
VMESS_VERSION = 1
OPTION_CHUNK_STREAM = 1
OPTION_CHUNK_MASKING = 4

class VMess:
    """VMess protocol header."""
    def __init__(self, user_id: Union[str, uuid.UUID], alter_id: int = 0):
        """
        Initialize VMess protocol.
        
        Args:
            user_id: User UUID
            alter_id: Alter ID for enhanced security
        """
        if isinstance(user_id, str):
            self.user_id = uuid.UUID(user_id)
        else:
            self.user_id = user_id
        
        self.alter_id = alter_id
        self.timestamp = int(time.time())
        
    def generate_auth_id(self, timestamp: Optional[int] = None) -> bytes:
        """
        Generate authentication ID.
        
        Args:
            timestamp: Optional timestamp to use
            
        Returns:
            Authentication ID bytes
        """
        if timestamp is None:
            timestamp = self.timestamp
            
        # CRC-32 as specified in VMess protocol
        # In a real implementation, this would use proper CRC32
        h = hashlib.md5()
        h.update(self.user_id.bytes)
        h.update(struct.pack('>I', timestamp))
        return h.digest()[:4]
        
    def generate_request_header(self, command: int, target_host: str, 
                                target_port: int) -> bytes:
        """
        Generate VMess request header.
        
        Args:
            command: Command type (typically 1 for TCP)
            target_host: Target hostname
            target_port: Target port
            
        Returns:
            Encoded header bytes
        """
        # Generate IV and key for this request
        iv = random.randbytes(16)
        key = random.randbytes(16)
        
        # Request header
        header = bytearray()
        
        # Version
        header.append(VMESS_VERSION)
        
        # IV and key
        header.extend(iv)
        header.extend(key)
        
        # Response auth
        response_auth = random.randbytes(1)[0]
        header.append(response_auth)
        
        # Option
        option = 0
        header.append(option)
        
        # Padding length and security
        padding_len = random.randint(0, 15)
        security = 0  # AES-128-CFB as default
        mixed = (padding_len << 4) | security
        header.append(mixed)
        
        # Reserved
        header.append(0)
        
        # Command
        header.append(command)
        
        # Port (big-endian)
        header.extend(struct.pack('>H', target_port))
        
        # Address type and address
        try:
            # Try to parse as IPv4
            socket.inet_aton(target_host)
            header.append(1)  # IPv4
            header.extend(socket.inet_aton(target_host))
        except socket.error:
            try:
                # Try to parse as IPv6
                socket.inet_pton(socket.AF_INET6, target_host)
                header.append(3)  # IPv6
                header.extend(socket.inet_pton(socket.AF_INET6, target_host))
            except socket.error:
                # Treat as domain
                if len(target_host) > 255:
                    raise ValueError("Domain name too long")
                header.append(2)  # Domain
                header.append(len(target_host))
                header.extend(target_host.encode())
        
        # Add padding if needed
        if padding_len > 0:
            header.extend(random.randbytes(padding_len))
            
        # Calculate and append checksum (fnv1a hash in real implementation)
        checksum = self._fnv1a(bytes(header))
        header.extend(checksum.to_bytes(4, 'big'))
        
        # Encrypt the header using AES-128-CFB with key derived from user ID
        # This is a simplified encryption for demonstration
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad
        
        # Derive encryption key from user ID
        md5 = hashlib.md5()
        md5.update(self.user_id.bytes)
        enc_key = md5.digest()
        
        # Encrypt header using AES-128-CFB
        cipher = AES.new(enc_key, AES.MODE_CFB, iv=iv[:16])
        encrypted_header = cipher.encrypt(bytes(header))
        
        # Final request: auth_id + encrypted_header
        auth_id = self.generate_auth_id()
        
        return auth_id + encrypted_header
    
    def _fnv1a(self, data: bytes) -> int:
        """
        FNV-1a hash algorithm used in VMess.
        
        Args:
            data: Data to hash
            
        Returns:
            Hash value
        """
        # Constants for FNV-1a 32-bit
        FNV_PRIME = 0x01000193
        FNV_OFFSET_BASIS = 0x811C9DC5
        
        # Calculate hash
        hash_val = FNV_OFFSET_BASIS
        for byte in data:
            hash_val ^= byte
            hash_val = (hash_val * FNV_PRIME) & 0xFFFFFFFF
            
        return hash_val

class VMessProtocol:
    """
    VMess protocol implementation for the VPN service.
    
    This protocol is designed for V2Ray and is effective against DPI.
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize the VMess protocol handler.
        
        Args:
            config: Configuration options
        """
        self.config = config or {}
        self.user_id = self.config.get('user_id', str(uuid.uuid4()))
        self.alter_id = self.config.get('alter_id', 0)
        self.connections = {}
        
    async def handle_connection(self, reader: asyncio.StreamReader, 
                               writer: asyncio.StreamWriter) -> None:
        """
        Handle a client connection.
        
        Args:
            reader: StreamReader for reading client data
            writer: StreamWriter for writing data to client
        """
        peer = writer.get_extra_info('peername')
        conn_id = f"{peer[0]}:{peer[1]}"
        logger.info(f"New VMess connection from {conn_id}")
        
        try:
            # Read the first packet which contains the VMess header
            header_data = await reader.read(4096)
            if len(header_data) < 16:  # Minimum header size
                logger.warning(f"Invalid VMess header from {conn_id}")
                return
                
            # Process the header
            try:
                target_host, target_port = await self._process_header(header_data)
                if not target_host or not target_port:
                    logger.warning(f"Failed to process VMess header from {conn_id}")
                    return
                    
                logger.info(f"VMess connection from {conn_id} to {target_host}:{target_port}")
                
                # Connect to the target
                target_reader, target_writer = await asyncio.open_connection(
                    target_host, target_port
                )
                
                # Store connection info
                self.connections[conn_id] = {
                    'client_reader': reader,
                    'client_writer': writer,
                    'target_reader': target_reader,
                    'target_writer': target_writer,
                    'created_at': time.time()
                }
                
                # Start bidirectional forwarding
                client_to_target = asyncio.create_task(
                    self._forward_stream(
                        reader, target_writer, self._decode_vmess_data, conn_id
                    )
                )
                
                target_to_client = asyncio.create_task(
                    self._forward_stream(
                        target_reader, writer, self._encode_vmess_data, conn_id
                    )
                )
                
                # Wait for either stream to finish
                await asyncio.gather(client_to_target, target_to_client, return_exceptions=True)
                
            except Exception as e:
                logger.error(f"Error processing VMess connection from {conn_id}: {str(e)}")
                
        except Exception as e:
            logger.error(f"Error handling VMess connection from {conn_id}: {str(e)}")
        finally:
            # Clean up
            await self._close_connection(conn_id)
    
    async def _process_header(self, header_data: bytes) -> Tuple[Optional[str], Optional[int]]:
        """
        Process VMess header to extract target host and port.
        
        Args:
            header_data: VMess header data
            
        Returns:
            Tuple of (target_host, target_port)
        """
        # This is a simplified implementation
        # A real VMess implementation would properly decode and validate the header
        
        try:
            # Extract auth ID (first 4 bytes)
            auth_id = header_data[:4]
            
            # In a real implementation, we would:
            # 1. Verify the auth ID against allowed users
            # 2. Decrypt the header using the user's key
            # 3. Parse the decrypted header to get command, address, port, etc.
            
            # For demonstration, we'll decode a simplified format:
            # After auth_id (4 bytes), let's assume:
            # - 1 byte for version
            # - 16 bytes for request IV
            # - 16 bytes for request Key
            # - 1 byte for response auth
            # - 1 byte for options
            # - 1 byte for padding/security
            # - 1 byte for reserved
            # - 1 byte for command
            # - 2 bytes for port
            # - 1 byte for address type
            # - variable length for address
            
            # Skip to the port field (4 + 1 + 16 + 16 + 1 + 1 + 1 + 1 + 1 = 42)
            port_data = header_data[42:44]
            port = struct.unpack('>H', port_data)[0]
            
            # Address type
            addr_type = header_data[44]
            
            if addr_type == 1:  # IPv4
                ip_bytes = header_data[45:49]
                host = socket.inet_ntoa(ip_bytes)
            elif addr_type == 3:  # IPv6
                ip_bytes = header_data[45:61]
                host = socket.inet_ntop(socket.AF_INET6, ip_bytes)
            elif addr_type == 2:  # Domain
                length = header_data[45]
                domain_bytes = header_data[46:46+length]
                host = domain_bytes.decode('utf-8')
            else:
                logger.warning(f"Unknown address type: {addr_type}")
                return None, None
                
            return host, port
            
        except Exception as e:
            logger.error(f"Error processing VMess header: {str(e)}")
            return None, None
    
    async def _forward_stream(self, reader: asyncio.StreamReader, 
                             writer: asyncio.StreamWriter,
                             process_func, conn_id: str) -> None:
        """
        Forward data from reader to writer with processing.
        
        Args:
            reader: Source stream reader
            writer: Destination stream writer
            process_func: Function to process data before forwarding
            conn_id: Connection identifier
        """
        try:
            while True:
                data = await reader.read(8192)
                if not data:
                    break
                    
                # Process data
                processed_data = await process_func(data, conn_id)
                if processed_data:
                    writer.write(processed_data)
                    await writer.drain()
                
        except Exception as e:
            logger.error(f"Error in VMess stream forwarding for {conn_id}: {str(e)}")
        finally:
            # Signal EOF
            try:
                writer.write_eof()
            except Exception:
                pass
    
    async def _decode_vmess_data(self, data: bytes, conn_id: str) -> bytes:
        """
        Decode VMess data from client.
        
        Args:
            data: Encoded data
            conn_id: Connection identifier
            
        Returns:
            Decoded data
        """
        # In a real implementation, this would decrypt and verify VMess data
        # For simplicity, we'll just return the raw data
        return data
    
    async def _encode_vmess_data(self, data: bytes, conn_id: str) -> bytes:
        """
        Encode data as VMess for client.
        
        Args:
            data: Raw data
            conn_id: Connection identifier
            
        Returns:
            VMess encoded data
        """
        # In a real implementation, this would encrypt and format data as VMess
        # For simplicity, we'll just return the raw data
        return data
    
    async def _close_connection(self, conn_id: str) -> None:
        """
        Close a connection and clean up resources.
        
        Args:
            conn_id: Connection identifier
        """
        if conn_id in self.connections:
            conn = self.connections[conn_id]
            
            # Close client connection
            try:
                conn['client_writer'].close()
                await conn['client_writer'].wait_closed()
            except Exception:
                pass
                
            # Close target connection
            try:
                conn['target_writer'].close()
                await conn['target_writer'].wait_closed()
            except Exception:
                pass
                
            # Remove from connections dict
            del self.connections[conn_id]
            logger.info(f"Closed VMess connection {conn_id}")
    
    async def connect(self, target_host: str, target_port: int) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """
        Create a new VMess connection to target.
        
        Args:
            target_host: Target hostname
            target_port: Target port
            
        Returns:
            Tuple of (reader, writer)
        """
        # Connect to VMess server
        server_host = self.config.get('server_host')
        server_port = self.config.get('server_port')
        
        if not server_host or not server_port:
            raise ValueError("VMess server host and port must be specified")
            
        logger.info(f"Connecting to VMess server at {server_host}:{server_port}")
        
        # Create VMess header
        vmess = VMess(self.user_id, self.alter_id)
        header = vmess.generate_request_header(1, target_host, target_port)
        
        # Connect to server
        reader, writer = await asyncio.open_connection(server_host, server_port)
        
        # Send header
        writer.write(header)
        await writer.drain()
        
        return reader, writer

# Factory function
def create_vmess_protocol(config: Dict[str, Any] = None) -> VMessProtocol:
    """
    Create a VMess protocol handler.
    
    Args:
        config: Configuration options
        
    Returns:
        VMess protocol instance
    """
    return VMessProtocol(config) 