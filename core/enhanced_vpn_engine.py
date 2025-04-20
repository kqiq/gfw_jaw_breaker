"""
Enhanced VPN Engine with advanced features including connection pooling,
protocol switching, and QUIC support.
"""
import asyncio
import logging
import socket
import ssl
import time
import uuid
from typing import Dict, Any, Optional, Tuple, List

from utils.encryption import encrypt_data, decrypt_data
from core.gfw_evasion import GFWEvasionManager
from core.connection_pool import ConnectionPool
from protocols.adaptive_protocol_switcher import AdaptiveProtocolSwitcher
from protocols.quic_protocol import QUICProtocol
from config.config import (
    BUFFER_SIZE, 
    ENCRYPTION_METHOD,
    LOG_LEVEL,
    GFW_EVASION_ENABLED,
    USE_CONNECTION_POOL,
    ENABLE_ADAPTIVE_PROTOCOL,
    ENABLE_QUIC
)

# Configure logging
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class EnhancedVPNEngine:
    """Enhanced VPN Engine with advanced features."""
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize the Enhanced VPN Engine.
        
        Args:
            config: Dictionary of configuration options that override defaults
        """
        self.config = config or {}
        self.connections = {}
        self.running = False
        self.start_time = 0
        
        # Initialize GFW evasion component
        self.gfw_evasion_enabled = self.config.get('gfw_evasion_enabled', GFW_EVASION_ENABLED)
        self.gfw_evasion = GFWEvasionManager(self.config) if self.gfw_evasion_enabled else None
        
        # Initialize connection pool
        self.use_connection_pool = self.config.get('use_connection_pool', USE_CONNECTION_POOL)
        self.connection_pool = ConnectionPool(self.config) if self.use_connection_pool else None
        
        # Initialize protocol switcher
        self.enable_adaptive_protocol = self.config.get('enable_adaptive_protocol', ENABLE_ADAPTIVE_PROTOCOL)
        self.protocol_switcher = AdaptiveProtocolSwitcher(self.config) if self.enable_adaptive_protocol else None
        
        # Initialize QUIC support
        self.enable_quic = self.config.get('enable_quic', ENABLE_QUIC)
        self.quic_protocol = QUICProtocol(self.config) if self.enable_quic else None
        
        # Server instances
        self.tcp_server = None
        self.udp_transport = None
        self.udp_protocol = None
        
        logger.info("Enhanced VPN Engine initialized")
        
    async def start_server(self, host: str, port: int, quic_port: Optional[int] = None) -> None:
        """
        Start the VPN server on the specified host and port.
        
        Args:
            host: Hostname or IP address to bind to
            port: Port number to listen on for TCP
            quic_port: Optional separate port for QUIC (UDP)
        """
        # Initialize components
        if self.gfw_evasion:
            await self.gfw_evasion.initialize()
            
        if self.connection_pool:
            await self.connection_pool.start()
            
        if self.protocol_switcher:
            await self.protocol_switcher.start()
            
        # Start the TCP server
        self.tcp_server = await asyncio.start_server(
            self.handle_client, host, port
        )
        
        # Start QUIC server if enabled
        if self.enable_quic and self.quic_protocol:
            quic_listen_port = quic_port or (port + 1)  # Use next port if not specified
            # Start in a background task to not block
            asyncio.create_task(self.quic_protocol.start_server(host, quic_listen_port))
            logger.info(f"QUIC Server starting on {host}:{quic_listen_port}")
            
        self.running = True
        self.start_time = time.time()
        logger.info(f"Enhanced VPN Server started on {host}:{port}")
        
        # Start serving TCP connections
        async with self.tcp_server:
            await self.tcp_server.serve_forever()
    
    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """
        Handle a client connection.
        
        Args:
            reader: StreamReader for reading client data
            writer: StreamWriter for writing data to client
        """
        addr = writer.get_extra_info('peername')
        client_id = f"{addr[0]}:{addr[1]}"
        connection_id = str(uuid.uuid4())
        logger.info(f"New client connected: {client_id} (connection_id: {connection_id})")
        
        # Store connection info
        conn_info = {
            'reader': reader,
            'writer': writer,
            'connect_time': time.time(),
            'bytes_sent': 0,
            'bytes_received': 0,
            'remote_addr': addr[0],
            'remote_port': addr[1],
            'connection_id': connection_id,
            'packet_count': 0,
            'tcp_options': writer.get_extra_info('socket').getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
        }
        self.connections[client_id] = conn_info
        
        # Register with GFW evasion
        if self.gfw_evasion:
            self.gfw_evasion.new_connection(conn_info)
        
        try:
            # First packet determines the protocol
            first_data = await reader.read(BUFFER_SIZE)
            if not first_data:
                return
                
            # Update statistics
            conn_info['bytes_received'] += len(first_data)
            conn_info['packet_count'] += 1
            conn_info['first_data_time'] = time.time()
            
            # Check for GFW probes
            if self.gfw_evasion:
                continue_processing, response = await self.gfw_evasion.process_incoming_packet(
                    first_data, 
                    {
                        'remote_addr': addr[0],
                        'packet_count': conn_info['packet_count'],
                        'connection_id': connection_id,
                        'first_data_time': conn_info.get('first_data_time'),
                        'connection_time': conn_info['connect_time'],
                        'tcp_options': conn_info.get('tcp_options', {})
                    }
                )
                
                # If probe detected, send response and stop processing
                if not continue_processing:
                    if response:
                        writer.write(response)
                        await writer.drain()
                    return
            
            # Determine protocol or use adaptive protocol switcher
            if self.protocol_switcher:
                protocol_handler = self.protocol_switcher.get_current_handler()
                if protocol_handler:
                    logger.info(f"Using protocol: {self.protocol_switcher.get_current_protocol()}")
                    
                    # Create a new StreamReader with the first data already in it
                    new_reader = asyncio.StreamReader()
                    new_reader.feed_data(first_data)
                    
                    # Handle the connection with the selected protocol
                    await protocol_handler.handle_connection(new_reader, writer)
                    return
            
            # Process the first data packet ourselves if no protocol switcher
            await self._process_data_packet(first_data, client_id, connection_id)
            
            # Process subsequent data
            while True:
                data = await reader.read(BUFFER_SIZE)
                if not data:
                    break
                
                # Update statistics
                conn_info['bytes_received'] += len(data)
                conn_info['packet_count'] += 1
                
                # Process data
                await self._process_data_packet(data, client_id, connection_id)
                
        except Exception as e:
            logger.error(f"Error handling client {client_id}: {str(e)}")
        finally:
            # Clean up
            writer.close()
            await writer.wait_closed()
            if client_id in self.connections:
                del self.connections[client_id]
            logger.info(f"Client disconnected: {client_id}")
    
    async def _process_data_packet(self, data: bytes, client_id: str, connection_id: str) -> None:
        """
        Process a data packet from a client.
        
        Args:
            data: Raw data from client
            client_id: Client identifier
            connection_id: Unique connection identifier
        """
        if client_id not in self.connections:
            return
            
        conn_info = self.connections[client_id]
        writer = conn_info['writer']
        
        # Check for GFW probes (except for first packet which is checked in handle_client)
        if self.gfw_evasion and conn_info['packet_count'] > 1:
            continue_processing, response = await self.gfw_evasion.process_incoming_packet(
                data, 
                {
                    'remote_addr': conn_info['remote_addr'],
                    'packet_count': conn_info['packet_count'],
                    'connection_id': connection_id,
                    'first_data_time': conn_info.get('first_data_time'),
                    'connection_time': conn_info['connect_time'],
                    'tcp_options': conn_info.get('tcp_options', {})
                }
            )
            
            # If probe detected, send response and stop processing
            if not continue_processing:
                if response:
                    writer.write(response)
                    await writer.drain()
                return
        
        # Process data (decrypt, route, etc.)
        decrypted_data = await decrypt_data(data, ENCRYPTION_METHOD)
        
        # Process the VPN request
        response_data = await self.process_vpn_request(decrypted_data, client_id)
        
        # Encrypt response
        encrypted_response = await encrypt_data(response_data, ENCRYPTION_METHOD)
        
        # Apply GFW evasion techniques to outgoing data
        if self.gfw_evasion:
            encrypted_response = await self.gfw_evasion.process_outgoing_packet(
                encrypted_response,
                {
                    'connection_id': connection_id,
                    'packet_count': conn_info['packet_count'],
                    'is_response': True
                }
            )
        
        # Send response back to client
        writer.write(encrypted_response)
        await writer.drain()
        
        # Update statistics
        conn_info['bytes_sent'] += len(encrypted_response)
    
    async def process_vpn_request(self, data: bytes, client_id: str) -> bytes:
        """
        Process VPN request data.
        
        Args:
            data: Decrypted client data
            client_id: Client identifier
            
        Returns:
            Processed data to send back to client
        """
        # Parse the request and extract target information
        # This is a simplified implementation
        # In a real VPN, you would parse complex protocols
        
        # For demonstration, assume the request format is:
        # [1 byte: request type][variable: target host/path][2 bytes: target port][remaining: payload]
        
        if len(data) < 4:  # Minimum valid request
            return b"INVALID REQUEST: Too short"
            
        request_type = data[0]
        
        # Different request types:
        # 0x01: Connect to host (direct)
        # 0x02: HTTP proxy request
        # 0x03: SOCKS proxy request
        
        if request_type == 0x01:  # Direct connection
            # Extract host and port
            host_length = data[1]
            if 2 + host_length + 2 > len(data):
                return b"INVALID REQUEST: Malformed host"
                
            host = data[2:2+host_length].decode('utf-8', errors='ignore')
            port = int.from_bytes(data[2+host_length:4+host_length], byteorder='big')
            payload = data[4+host_length:]
            
            # Use connection pool if enabled
            if self.use_connection_pool and self.connection_pool:
                target_reader, target_writer, is_new = await self.connection_pool.get_connection(
                    (host, port),
                    create_func=self.connect_to_target
                )
            else:
                target_reader, target_writer = await self.connect_to_target(host, port)
                is_new = True
                
            if is_new and payload:
                # Send initial payload
                target_writer.write(payload)
                await target_writer.drain()
                
            # Read response
            response = await target_reader.read(BUFFER_SIZE)
            
            # Release connection back to pool if using it
            if self.use_connection_pool and self.connection_pool:
                await self.connection_pool.release_connection(target_reader, target_writer)
                
            return response
            
        elif request_type == 0x02:  # HTTP proxy
            # Implement HTTP proxy logic
            return b"HTTP PROXY NOT IMPLEMENTED"
            
        elif request_type == 0x03:  # SOCKS proxy
            # Implement SOCKS proxy logic
            return b"SOCKS PROXY NOT IMPLEMENTED"
            
        else:
            return b"INVALID REQUEST: Unknown request type"
    
    async def connect_to_target(self, target_host: str, target_port: int) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """
        Connect to a target server.
        
        Args:
            target_host: Target hostname
            target_port: Target port number
            
        Returns:
            Tuple of (StreamReader, StreamWriter)
        """
        # Implement domain fronting, proxy chains, or other obfuscation here
        
        # For now, simple direct connection
        return await asyncio.open_connection(target_host, target_port)
    
    async def stop_server(self) -> None:
        """Stop the VPN server and clean up resources."""
        if not self.running:
            return
            
        self.running = False
        
        # Stop the TCP server
        if self.tcp_server:
            self.tcp_server.close()
            await self.tcp_server.wait_closed()
            
        # Stop the QUIC server
        if self.quic_protocol:
            await self.quic_protocol.stop()
            
        # Stop other components
        if self.connection_pool:
            await self.connection_pool.stop()
            
        if self.protocol_switcher:
            await self.protocol_switcher.stop()
            
        # Close all client connections
        for client_id, conn_info in list(self.connections.items()):
            try:
                conn_info['writer'].close()
                await conn_info['writer'].wait_closed()
            except Exception:
                pass
                
        self.connections.clear()
        logger.info("Enhanced VPN Server stopped") 