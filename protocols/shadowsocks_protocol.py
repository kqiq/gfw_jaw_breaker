"""
Shadowsocks protocol implementation.
"""
import asyncio
import logging
import random
import socket
import struct
import time
from typing import Dict, Any, Optional, Tuple, List

from utils.encryption import encrypt_data, decrypt_data
from config.config import LOG_LEVEL

# Configure logging
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# SOCKS5 constants
SOCKS_VER = 0x05
SOCKS_CMD_CONNECT = 0x01
SOCKS_CMD_BIND = 0x02
SOCKS_CMD_UDP = 0x03
SOCKS_IPV4 = 0x01
SOCKS_DOMAIN = 0x03
SOCKS_IPV6 = 0x04
SOCKS_RSV = 0x00
SOCKS_SUCCESS = 0x00

class ShadowsocksProtocol:
    """
    Shadowsocks protocol implementation for the VPN service.
    
    This protocol is based on the SOCKS5 protocol with encryption.
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize the Shadowsocks protocol handler.
        
        Args:
            config: Configuration options
        """
        self.config = config or {}
        self.encryption_method = self.config.get('encryption_method', 'aes-256-gcm')
        self.password = self.config.get('password', 'default_password')
        
        # For simple implementation, we use a fixed key
        # In a real implementation, key would be derived from password and method
        self.key = None
        self.connections = {}
        
    async def init_key(self) -> bytes:
        """Initialize the encryption key."""
        # In a real implementation, this would use a proper key derivation function
        if not self.key:
            from utils.encryption import generate_key
            self.key = await generate_key(self.encryption_method, self.password)
        return self.key
    
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
        logger.info(f"New Shadowsocks connection from {conn_id}")
        
        await self.init_key()
        
        try:
            # First data packet is encrypted in Shadowsocks
            encrypted_data = await reader.read(4096)
            if not encrypted_data:
                logger.warning(f"Empty initial packet from {conn_id}")
                return
                
            # Decrypt the initial data
            decrypted_data = await decrypt_data(encrypted_data, self.encryption_method, self.key)
            
            # Parse the SOCKS5-like request
            if len(decrypted_data) < 3:
                logger.warning(f"Invalid request from {conn_id}")
                return
                
            command = decrypted_data[0]
            addr_type = decrypted_data[1]
            
            # Extract the target address based on address type
            target_host, target_port, header_length = await self._parse_address(
                decrypted_data[1:], addr_type
            )
            
            if not target_host or not target_port:
                logger.warning(f"Invalid target address from {conn_id}")
                return
                
            logger.info(f"Connection from {conn_id} to {target_host}:{target_port}")
            
            # Connect to the target
            try:
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
                
                # Forward any remaining data to the target
                if header_length < len(decrypted_data):
                    remaining_data = decrypted_data[header_length:]
                    target_writer.write(remaining_data)
                    await target_writer.drain()
                
                # Start bidirectional forwarding
                client_to_target = asyncio.create_task(
                    self._forward_stream(
                        reader, target_writer, self._decrypt_client_data, conn_id
                    )
                )
                
                target_to_client = asyncio.create_task(
                    self._forward_stream(
                        target_reader, writer, self._encrypt_target_data, conn_id
                    )
                )
                
                # Wait for either stream to finish
                await asyncio.gather(client_to_target, target_to_client, return_exceptions=True)
                
            except Exception as e:
                logger.error(f"Error connecting to target {target_host}:{target_port}: {str(e)}")
                
                # Send failure response
                response = struct.pack(
                    "!BBBBIH", SOCKS_VER, 0x04, SOCKS_RSV, SOCKS_IPV4, 0, 0
                )
                encrypted_response = await encrypt_data(
                    response, self.encryption_method, self.key
                )
                writer.write(encrypted_response)
                await writer.drain()
                
        except Exception as e:
            logger.error(f"Error handling Shadowsocks connection from {conn_id}: {str(e)}")
        finally:
            # Clean up
            await self._close_connection(conn_id)
            
    async def _parse_address(self, data: bytes, addr_type: int) -> Tuple[str, int, int]:
        """
        Parse the address from a Shadowsocks request.
        
        Args:
            data: Request data
            addr_type: Address type (IPv4, domain, IPv6)
            
        Returns:
            Tuple of (host, port, header_length)
        """
        if addr_type == SOCKS_IPV4:
            if len(data) < 7:  # 1 (atyp) + 4 (ipv4) + 2 (port)
                return None, None, 0
            
            # IPv4 address (4 bytes)
            host = socket.inet_ntop(socket.AF_INET, data[1:5])
            port = int.from_bytes(data[5:7], byteorder='big')
            header_length = 7  # 1 (atyp) + 4 (ipv4) + 2 (port)
            
        elif addr_type == SOCKS_DOMAIN:
            if len(data) < 2:
                return None, None, 0
                
            domain_len = data[1]
            if len(data) < 2 + domain_len + 2:
                return None, None, 0
                
            # Domain name (variable length)
            host = data[2:2+domain_len].decode('utf-8', errors='ignore')
            port = int.from_bytes(data[2+domain_len:4+domain_len], byteorder='big')
            header_length = 4 + domain_len  # 1 (atyp) + 1 (len) + domain_len + 2 (port)
            
        elif addr_type == SOCKS_IPV6:
            if len(data) < 19:  # 1 (atyp) + 16 (ipv6) + 2 (port)
                return None, None, 0
                
            # IPv6 address (16 bytes)
            host = socket.inet_ntop(socket.AF_INET6, data[1:17])
            port = int.from_bytes(data[17:19], byteorder='big')
            header_length = 19  # 1 (atyp) + 16 (ipv6) + 2 (port)
            
        else:
            return None, None, 0
            
        return host, port, header_length
    
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
                    
                # Process data (encrypt/decrypt)
                processed_data = await process_func(data, conn_id)
                
                writer.write(processed_data)
                await writer.drain()
                
        except Exception as e:
            logger.error(f"Error in stream forwarding for {conn_id}: {str(e)}")
        finally:
            # Signal EOF
            writer.write_eof()
            
    async def _decrypt_client_data(self, data: bytes, conn_id: str) -> bytes:
        """Decrypt data from client."""
        try:
            return await decrypt_data(data, self.encryption_method, self.key)
        except Exception as e:
            logger.error(f"Error decrypting data from {conn_id}: {str(e)}")
            return data
    
    async def _encrypt_target_data(self, data: bytes, conn_id: str) -> bytes:
        """Encrypt data from target."""
        try:
            return await encrypt_data(data, self.encryption_method, self.key)
        except Exception as e:
            logger.error(f"Error encrypting data for {conn_id}: {str(e)}")
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
            logger.info(f"Closed connection {conn_id}")

# Factory function
def create_shadowsocks_protocol(config: Dict[str, Any] = None) -> ShadowsocksProtocol:
    """
    Create a Shadowsocks protocol handler.
    
    Args:
        config: Configuration options
        
    Returns:
        ShadowsocksProtocol instance
    """
    return ShadowsocksProtocol(config) 