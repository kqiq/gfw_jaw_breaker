"""
Trojan protocol implementation.

Trojan is a lightweight protocol designed to bypass GFW by mimicking HTTPS traffic.
"""
import asyncio
import logging
import socket
import ssl
import struct
import time
import hashlib
from typing import Dict, Any, Optional, Tuple, List, Union, Set

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

class TrojanProtocol:
    """
    Trojan protocol implementation for the VPN service.
    
    Trojan is designed to mimic HTTPS traffic to evade detection.
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize the Trojan protocol handler.
        
        Args:
            config: Configuration options
        """
        self.config = config or {}
        self.password = self.config.get('password', 'default_password')
        self.connections = {}
        
        # Generate password hash
        self.password_hash = self._generate_password_hash(self.password)
        
        # SSL context
        self.ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        
        # Try to load certificate and key if specified in config
        cert_file = self.config.get('cert_file')
        key_file = self.config.get('key_file')
        
        if cert_file and key_file:
            try:
                self.ssl_context.load_cert_chain(cert_file, key_file)
                logger.info(f"Loaded TLS certificate from {cert_file}")
            except Exception as e:
                logger.error(f"Failed to load TLS certificate: {str(e)}")
    
    def _generate_password_hash(self, password: str) -> str:
        """
        Generate SHA-224 hash of password in hexadecimal format.
        
        Args:
            password: Password string
            
        Returns:
            SHA-224 hash in hexadecimal
        """
        sha224 = hashlib.sha224()
        sha224.update(password.encode())
        return sha224.hexdigest()
    
    async def start_server(self, host: str, port: int) -> asyncio.Server:
        """
        Start Trojan server.
        
        Args:
            host: Host address to bind to
            port: Port to listen on
            
        Returns:
            AsyncIO server instance
        """
        server = await asyncio.start_server(
            self.handle_connection, host, port, ssl=self.ssl_context
        )
        logger.info(f"Trojan server started on {host}:{port}")
        return server
        
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
        logger.info(f"New Trojan connection from {conn_id}")
        
        try:
            # Read Trojan header
            header = await reader.read(56 + 2)  # SHA-224 hash (56 hex chars) + CRLF
            if len(header) < 58:
                logger.warning(f"Invalid Trojan header length from {conn_id}")
                return
                
            # Validate password hash
            recv_hash = header[:56].decode('ascii')
            if recv_hash != self.password_hash:
                logger.warning(f"Invalid password hash from {conn_id}")
                # To avoid timing attacks, we'll still read the command and pretend to process
                await self._handle_invalid_auth(reader, writer)
                return
                
            # Check for CRLF
            if header[56:58] != b'\r\n':
                logger.warning(f"Invalid header format from {conn_id}")
                return
                
            # Read command byte
            command = await reader.read(1)
            if not command:
                logger.warning(f"No command received from {conn_id}")
                return
                
            command_byte = command[0]
                
            # Read address type
            addr_type = await reader.read(1)
            if not addr_type:
                logger.warning(f"No address type received from {conn_id}")
                return
                
            addr_type_byte = addr_type[0]
            
            # Extract target address
            target_host, target_port = await self._parse_address(reader, addr_type_byte)
            if not target_host or not target_port:
                logger.warning(f"Failed to parse target address from {conn_id}")
                return
                
            # Check for CRLF
            crlf = await reader.read(2)
            if crlf != b'\r\n':
                logger.warning(f"Missing CRLF after address from {conn_id}")
                return
                
            logger.info(f"Trojan connection from {conn_id} to {target_host}:{target_port}")
            
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
                
                # Start bidirectional forwarding
                client_to_target = asyncio.create_task(
                    self._forward_stream(reader, target_writer, conn_id)
                )
                
                target_to_client = asyncio.create_task(
                    self._forward_stream(target_reader, writer, conn_id)
                )
                
                # Wait for either stream to finish
                await asyncio.gather(client_to_target, target_to_client, return_exceptions=True)
                
            except Exception as e:
                logger.error(f"Error connecting to target {target_host}:{target_port}: {str(e)}")
                
        except Exception as e:
            logger.error(f"Error handling Trojan connection from {conn_id}: {str(e)}")
        finally:
            # Clean up
            await self._close_connection(conn_id)
    
    async def _handle_invalid_auth(self, reader: asyncio.StreamReader, 
                                  writer: asyncio.StreamWriter) -> None:
        """
        Handle invalid authentication by responding as a normal HTTPS server would.
        
        Args:
            reader: Client reader
            writer: Client writer
        """
        # Read some data to look like we're processing normally
        await reader.read(1024)
        
        # Respond with a generic HTTP 400 error
        response = (
            b"HTTP/1.1 400 Bad Request\r\n"
            b"Server: nginx/1.18.0\r\n"
            b"Date: " + time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime()).encode() + b"\r\n"
            b"Content-Type: text/html\r\n"
            b"Content-Length: 166\r\n"
            b"Connection: close\r\n"
            b"\r\n"
            b"<html>\r\n"
            b"<head><title>400 Bad Request</title></head>\r\n"
            b"<body>\r\n"
            b"<center><h1>400 Bad Request</h1></center>\r\n"
            b"<hr><center>nginx/1.18.0</center>\r\n"
            b"</body>\r\n"
            b"</html>\r\n"
        )
        
        writer.write(response)
        await writer.drain()
    
    async def _parse_address(self, reader: asyncio.StreamReader, 
                            addr_type: int) -> Tuple[Optional[str], Optional[int]]:
        """
        Parse address from Trojan request.
        
        Args:
            reader: StreamReader to read from
            addr_type: Address type byte
            
        Returns:
            Tuple of (host, port)
        """
        try:
            if addr_type == SOCKS_IPV4:  # IPv4
                # Read 4 bytes for IPv4
                ip_data = await reader.read(4)
                if len(ip_data) != 4:
                    return None, None
                    
                host = socket.inet_ntoa(ip_data)
                
            elif addr_type == SOCKS_DOMAIN:  # Domain
                # Read domain length
                len_data = await reader.read(1)
                if not len_data:
                    return None, None
                    
                domain_len = len_data[0]
                
                # Read domain
                domain_data = await reader.read(domain_len)
                if len(domain_data) != domain_len:
                    return None, None
                    
                host = domain_data.decode('utf-8', errors='ignore')
                
            elif addr_type == SOCKS_IPV6:  # IPv6
                # Read 16 bytes for IPv6
                ip_data = await reader.read(16)
                if len(ip_data) != 16:
                    return None, None
                    
                host = socket.inet_ntop(socket.AF_INET6, ip_data)
                
            else:
                logger.warning(f"Unknown address type: {addr_type}")
                return None, None
                
            # Read port (2 bytes, big-endian)
            port_data = await reader.read(2)
            if len(port_data) != 2:
                return None, None
                
            port = struct.unpack('>H', port_data)[0]
            
            return host, port
            
        except Exception as e:
            logger.error(f"Error parsing address: {str(e)}")
            return None, None
    
    async def _forward_stream(self, reader: asyncio.StreamReader, 
                             writer: asyncio.StreamWriter,
                             conn_id: str) -> None:
        """
        Forward data stream.
        
        Args:
            reader: Source stream reader
            writer: Destination stream writer
            conn_id: Connection identifier
        """
        try:
            while True:
                data = await reader.read(8192)
                if not data:
                    break
                    
                writer.write(data)
                await writer.drain()
                
        except Exception as e:
            logger.error(f"Error in stream forwarding for {conn_id}: {str(e)}")
        finally:
            # Signal EOF
            try:
                writer.write_eof()
            except Exception:
                pass
    
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
            logger.info(f"Closed Trojan connection {conn_id}")
    
    async def connect(self, target_host: str, target_port: int) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """
        Create a new Trojan connection to target.
        
        Args:
            target_host: Target hostname
            target_port: Target port
            
        Returns:
            Tuple of (reader, writer)
        """
        # Connect to Trojan server
        server_host = self.config.get('server_host')
        server_port = self.config.get('server_port')
        
        if not server_host or not server_port:
            raise ValueError("Trojan server host and port must be specified")
            
        logger.info(f"Connecting to Trojan server at {server_host}:{server_port}")
        
        # Create SSL context for client
        ssl_context = ssl.create_default_context()
        
        # Connect with TLS
        reader, writer = await asyncio.open_connection(
            server_host, server_port, ssl=ssl_context
        )
        
        # Build and send Trojan request
        
        # Format: [password hash (56 bytes)][CRLF][command (1 byte)][address type (1 byte)][dest addr][dest port][CRLF]
        request = bytearray()
        
        # Password hash
        request.extend(self.password_hash.encode())
        
        # CRLF
        request.extend(b'\r\n')
        
        # Command (CONNECT)
        request.append(SOCKS_CMD_CONNECT)
        
        # Address type and address
        if self._is_ipv4(target_host):
            # IPv4
            request.append(SOCKS_IPV4)
            request.extend(socket.inet_aton(target_host))
        elif self._is_ipv6(target_host):
            # IPv6
            request.append(SOCKS_IPV6)
            request.extend(socket.inet_pton(socket.AF_INET6, target_host))
        else:
            # Domain
            if len(target_host) > 255:
                raise ValueError("Domain name too long")
                
            request.append(SOCKS_DOMAIN)
            request.append(len(target_host))
            request.extend(target_host.encode())
            
        # Port (big-endian)
        request.extend(struct.pack('>H', target_port))
        
        # CRLF
        request.extend(b'\r\n')
        
        # Send request
        writer.write(bytes(request))
        await writer.drain()
        
        return reader, writer
    
    def _is_ipv4(self, host: str) -> bool:
        """Check if string is an IPv4 address."""
        try:
            socket.inet_aton(host)
            return True
        except socket.error:
            return False
            
    def _is_ipv6(self, host: str) -> bool:
        """Check if string is an IPv6 address."""
        try:
            socket.inet_pton(socket.AF_INET6, host)
            return True
        except socket.error:
            return False

# Factory function
def create_trojan_protocol(config: Dict[str, Any] = None) -> TrojanProtocol:
    """
    Create a Trojan protocol handler.
    
    Args:
        config: Configuration options
        
    Returns:
        Trojan protocol instance
    """
    return TrojanProtocol(config) 