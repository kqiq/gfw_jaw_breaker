"""
Core VPN Engine module that handles basic VPN functionality.
"""
import asyncio
import logging
import socket
import ssl
import time
import uuid
from typing import Dict, Any, Optional, Tuple

from utils.encryption import encrypt_data, decrypt_data
from core.gfw_evasion import GFWEvasionManager
from config.config import (
    BUFFER_SIZE, 
    ENCRYPTION_METHOD,
    LOG_LEVEL,
    GFW_EVASION_ENABLED
)

# Configure logging
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class VPNEngine:
    """Core VPN Engine that handles traffic routing and encryption."""
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize the VPN Engine.
        
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
        
        logger.info("VPN Engine initialized")
        
    async def start_server(self, host: str, port: int) -> None:
        """
        Start the VPN server on the specified host and port.
        
        Args:
            host: Hostname or IP address to bind to
            port: Port number to listen on
        """
        # Initialize GFW evasion if enabled
        if self.gfw_evasion:
            await self.gfw_evasion.initialize()
        
        self.server = await asyncio.start_server(
            self.handle_client, host, port
        )
        self.running = True
        self.start_time = time.time()
        logger.info(f"VPN Server started on {host}:{port}")
        
        async with self.server:
            await self.server.serve_forever()
    
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
            while True:
                data = await reader.read(BUFFER_SIZE)
                if not data:
                    break
                
                # Update statistics
                conn_info['bytes_received'] += len(data)
                conn_info['packet_count'] += 1
                
                # First data packet timing (for probe detection)
                if conn_info['packet_count'] == 1:
                    conn_info['first_data_time'] = time.time()
                
                # Check for GFW probes
                if self.gfw_evasion:
                    continue_processing, response = await self.gfw_evasion.process_incoming_packet(
                        data, 
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
                        break
                
                # Process data (decrypt, route, etc.)
                decrypted_data = await decrypt_data(data, ENCRYPTION_METHOD)
                
                # Here you would implement your routing logic
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
                
        except Exception as e:
            logger.error(f"Error handling client {client_id}: {str(e)}")
        finally:
            # Clean up
            writer.close()
            await writer.wait_closed()
            if client_id in self.connections:
                del self.connections[client_id]
            logger.info(f"Client disconnected: {client_id}")
    
    async def process_vpn_request(self, data: bytes, client_id: str) -> bytes:
        """
        Process VPN request data.
        
        Args:
            data: Decrypted client data
            client_id: Client identifier
            
        Returns:
            Processed data to send back to client
        """
        # This is a simplified implementation
        # In a real VPN, you would parse the request, establish tunnels, etc.
        
        # Basic pass-through for now
        return data
    
    async def connect_to_target(self, target_host: str, target_port: int) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """
        Connect to a target server, optionally using domain fronting.
        
        Args:
            target_host: Target hostname
            target_port: Target port number
            
        Returns:
            Tuple of (reader, writer)
        """
        target_url = f"https://{target_host}:{target_port}"
        
        # Apply domain fronting if enabled
        if self.gfw_evasion:
            fronted_url, headers = await self.gfw_evasion.apply_domain_fronting(target_url)
            
            # Parse the fronted URL to extract host and port
            parts = fronted_url.split('://', 1)[1].split('/', 1)[0].split(':')
            fronted_host = parts[0]
            fronted_port = int(parts[1]) if len(parts) > 1 else 443
            
            # Create SSL context
            ssl_context = ssl.create_default_context()
            
            # Connect to the fronting domain
            reader, writer = await asyncio.open_connection(
                fronted_host, fronted_port, ssl=ssl_context
            )
            
            # Send SNI header with original host
            if target_host != fronted_host:
                writer.write(f"Host: {target_host}\r\n".encode())
                for header, value in headers.items():
                    writer.write(f"{header}: {value}\r\n".encode())
                writer.write(b"\r\n")
                await writer.drain()
                
            return reader, writer
        else:
            # Direct connection (no fronting)
            return await asyncio.open_connection(target_host, target_port)
    
    async def stop_server(self) -> None:
        """Stop the VPN server and close all connections."""
        if not self.running:
            return
            
        # Close all client connections
        for client_id, conn_info in self.connections.items():
            try:
                conn_info['writer'].close()
                await conn_info['writer'].wait_closed()
            except Exception as e:
                logger.error(f"Error closing connection to {client_id}: {str(e)}")
        
        # Clear connections dict
        self.connections.clear()
        
        # Close GFW evasion component
        if self.gfw_evasion:
            await self.gfw_evasion.close()
        
        # Close server
        self.server.close()
        await self.server.wait_closed()
        self.running = False
        logger.info("VPN Server stopped") 