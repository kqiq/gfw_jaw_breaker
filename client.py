#!/usr/bin/env python3
"""
Ultimate VPN Service - Client

This is the main entry point for running the VPN client.
"""
import asyncio
import argparse
import logging
import os
import signal
import sys
import time
from typing import Dict, Any, Optional, List

# Add local modules to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.vpn_engine import VPNEngine
from protocols.protocol_switcher import ProtocolSwitcher
from overlay.overlay_network import OverlayNetwork
from protocols.obfuscation import create_obfuscation_protocol
from config.config import (
    CLIENT_TIMEOUT,
    LOG_LEVEL,
    OBFUSCATION_ENABLED,
    DEFAULT_OBFUSCATION,
    DEFAULT_PROTOCOL
)

# Configure logging
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("client")

class VPNClient:
    """Main VPN Client class that orchestrates all components."""
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize the VPN client.
        
        Args:
            config: Configuration options
        """
        self.config = config or {}
        self.server_host = self.config.get('server_host')
        self.server_port = self.config.get('server_port')
        self.timeout = self.config.get('timeout', CLIENT_TIMEOUT)
        
        # Initialize components
        self.vpn_engine = VPNEngine(self.config)
        self.protocol_switcher = ProtocolSwitcher(self.config)
        self.overlay_network = OverlayNetwork(self.config)
        
        # Set up obfuscation
        self.obfuscation_enabled = self.config.get('obfuscation_enabled', OBFUSCATION_ENABLED)
        self.obfuscation_protocol = None
        
        if self.obfuscation_enabled:
            obfuscation_name = self.config.get('default_obfuscation', DEFAULT_OBFUSCATION)
            self.obfuscation_protocol = create_obfuscation_protocol(obfuscation_name, self.config)
            logger.info(f"Using obfuscation protocol: {obfuscation_name}")
        
        # Connection state
        self.running = False
        self.connection = None
        self.reader = None
        self.writer = None
    
    async def connect(self) -> bool:
        """
        Connect to the VPN server.
        
        Returns:
            True if connection successful, False otherwise
        """
        if not self.server_host or not self.server_port:
            logger.error("Server host and port must be specified")
            return False
            
        logger.info(f"Connecting to VPN server at {self.server_host}:{self.server_port}")
        
        try:
            # Start protocol switcher
            await self.protocol_switcher.start()
            
            # Establish connection using the overlay network
            callbacks = {
                'progress_callback': self._connection_progress_callback,
                'error_callback': self._connection_error_callback
            }
            
            # Create initial connection
            self.reader, self.writer = await asyncio.open_connection(
                self.server_host, self.server_port
            )
            
            self.running = True
            logger.info("Connected to VPN server successfully")
            
            # Start monitoring connection
            asyncio.create_task(self._monitor_connection())
            
            return True
            
        except Exception as e:
            logger.error(f"Connection failed: {str(e)}")
            return False
    
    async def disconnect(self) -> None:
        """Disconnect from the VPN server."""
        if not self.running:
            return
            
        logger.info("Disconnecting from VPN server...")
        
        self.running = False
        
        # Close connection
        if self.writer:
            try:
                self.writer.close()
                await self.writer.wait_closed()
            except Exception as e:
                logger.error(f"Error closing connection: {str(e)}")
        
        # Stop components
        await self.protocol_switcher.stop()
        
        logger.info("Disconnected from VPN server")
    
    async def send_vpn_request(self, data: bytes) -> Optional[bytes]:
        """
        Send a request through the VPN.
        
        Args:
            data: Data to send
            
        Returns:
            Response data if successful, None otherwise
        """
        if not self.running or not self.writer:
            logger.error("Not connected to VPN server")
            return None
            
        try:
            # Apply obfuscation if enabled
            if self.obfuscation_enabled and self.obfuscation_protocol:
                data = await self.obfuscation_protocol.obfuscate(data)
            
            # Send data
            self.writer.write(data)
            await self.writer.drain()
            
            # Read response
            response = await asyncio.wait_for(self.reader.read(65536), timeout=self.timeout)
            
            # Deobfuscate if necessary
            if self.obfuscation_enabled and self.obfuscation_protocol:
                response = await self.obfuscation_protocol.deobfuscate(response)
                
            return response
            
        except asyncio.TimeoutError:
            logger.error(f"Request timed out after {self.timeout} seconds")
            return None
        except Exception as e:
            logger.error(f"Error sending VPN request: {str(e)}")
            return None
    
    async def _monitor_connection(self) -> None:
        """Monitor the VPN connection for failures and reconnect if necessary."""
        while self.running:
            try:
                # Check if the connection is still alive by reading a small amount of data
                if not self.reader or self.reader.at_eof():
                    logger.warning("Connection lost, attempting to reconnect...")
                    await self._reconnect()
                
                # Sleep for a bit before checking again
                await asyncio.sleep(5)
                
            except Exception as e:
                logger.error(f"Error in connection monitor: {str(e)}")
                await asyncio.sleep(1)
    
    async def _reconnect(self) -> bool:
        """
        Attempt to reconnect to the VPN server.
        
        Returns:
            True if reconnection successful, False otherwise
        """
        # Close existing connection if any
        if self.writer:
            try:
                self.writer.close()
                await self.writer.wait_closed()
            except Exception:
                pass
            
        # Try to reconnect
        retry_count = 0
        max_retries = 5
        retry_delay = 2  # seconds
        
        while retry_count < max_retries:
            try:
                logger.info(f"Reconnection attempt {retry_count + 1}/{max_retries}...")
                self.reader, self.writer = await asyncio.open_connection(
                    self.server_host, self.server_port
                )
                logger.info("Reconnected successfully")
                return True
            except Exception as e:
                logger.error(f"Reconnection failed: {str(e)}")
                retry_count += 1
                retry_delay *= 1.5  # Exponential backoff
                await asyncio.sleep(retry_delay)
        
        logger.error("Failed to reconnect after multiple attempts")
        return False
    
    def _connection_progress_callback(self, current: int, total: int, 
                                     path_index: int = 0, path_count: int = 1) -> None:
        """Callback to track connection progress."""
        if path_count > 1:
            logger.debug(f"Connection progress on path {path_index+1}/{path_count}: {current}/{total}")
        else:
            logger.debug(f"Connection progress: {current}/{total}")
    
    def _connection_error_callback(self, error_msg: str) -> None:
        """Callback for connection errors."""
        logger.error(f"Connection error: {error_msg}")

async def main() -> None:
    """Main entry point for the client."""
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Ultimate VPN Client')
    parser.add_argument('--server', type=str, required=True, 
                        help='VPN server address (host:port)')
    parser.add_argument('--protocol', type=str, default=DEFAULT_PROTOCOL,
                        help='VPN protocol to use')
    parser.add_argument('--obfuscation', type=str, default=DEFAULT_OBFUSCATION,
                        help='Obfuscation method to use')
    parser.add_argument('--no-obfuscation', action='store_true',
                        help='Disable obfuscation')
    parser.add_argument('--timeout', type=int, default=CLIENT_TIMEOUT,
                        help='Connection timeout in seconds')
    parser.add_argument('--log-level', type=str, default=LOG_LEVEL,
                        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        help='Logging level')
    
    args = parser.parse_args()
    
    # Configure logging level from args
    logging.getLogger().setLevel(getattr(logging, args.log_level))
    
    # Parse server address
    if ':' in args.server:
        server_host, server_port_str = args.server.split(':')
        server_port = int(server_port_str)
    else:
        server_host = args.server
        server_port = 8443  # Default port
    
    # Create client config
    config = {
        'server_host': server_host,
        'server_port': server_port,
        'default_protocol': args.protocol,
        'default_obfuscation': args.obfuscation,
        'obfuscation_enabled': not args.no_obfuscation,
        'timeout': args.timeout,
        'log_level': args.log_level
    }
    
    # Create and start client
    client = VPNClient(config)
    
    # Set up signal handlers for graceful shutdown
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda: asyncio.create_task(client.disconnect()))
    
    try:
        # Connect to server
        connected = await client.connect()
        if not connected:
            logger.error("Failed to connect to VPN server")
            return
            
        # Wait for disconnection signal
        logger.info("VPN client connected. Press Ctrl+C to disconnect.")
        while client.running:
            await asyncio.sleep(1)
            
    except Exception as e:
        logger.error(f"Error in client: {str(e)}")
    finally:
        await client.disconnect()

if __name__ == "__main__":
    asyncio.run(main()) 