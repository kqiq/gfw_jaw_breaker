"""
Overlay Network module for bypassing internet firewalls like the Great Firewall (GFW).
"""
import asyncio
import logging
import random
import socket
import ssl
import time
from typing import Dict, List, Any, Optional, Tuple, Set, Callable

from config.config import (
    DOMAIN_FRONTING,
    USE_MULTIPATH,
    PACKET_FRAGMENTATION,
    LOG_LEVEL
)

# Configure logging
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class OverlayNetwork:
    """
    Overlay network that provides techniques to bypass internet censorship.
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize the overlay network.
        
        Args:
            config: Configuration options
        """
        self.config = config or {}
        self.domain_fronting = self.config.get('domain_fronting', DOMAIN_FRONTING)
        self.use_multipath = self.config.get('use_multipath', USE_MULTIPATH)
        self.packet_fragmentation = self.config.get('packet_fragmentation', PACKET_FRAGMENTATION)
        
        # CDN providers for domain fronting (if enabled)
        self.cdn_providers = [
            {
                'host': 'cdn.cloudflare.com',
                'fronting_domains': ['ajax.cloudflare.com', 'cdnjs.cloudflare.com']
            },
            {
                'host': 'cdn.fastly.com',
                'fronting_domains': ['cdn.fastly.net', 'fastly.net']
            },
            {
                'host': 'cdn.jsdelivr.net',
                'fronting_domains': ['cdn.jsdelivr.net', 'jsdelivr.net']
            }
        ]
        
        # Multipath settings
        self.max_paths = self.config.get('max_paths', 3)
        self.path_timeout = self.config.get('path_timeout', 10.0)
        
        # Fragment size for packet fragmentation (if enabled)
        self.fragment_size = self.config.get('fragment_size', 512)
        
        logger.info("Overlay Network initialized")
    
    async def send_data(self, data: bytes, destination: Tuple[str, int], 
                       callbacks: Dict[str, Callable] = None) -> Optional[bytes]:
        """
        Send data through the overlay network to bypass censorship.
        
        Args:
            data: Data to send
            destination: Destination (host, port)
            callbacks: Optional callbacks for status updates
            
        Returns:
            Response data if successful, None otherwise
        """
        if not callbacks:
            callbacks = {}
            
        # Apply selected techniques based on configuration
        processed_data = data
        
        # Apply packet fragmentation if enabled
        if self.packet_fragmentation:
            fragments = self.fragment_data(processed_data)
            if 'fragmentation_callback' in callbacks:
                callbacks['fragmentation_callback'](len(fragments))
            logger.debug(f"Data fragmented into {len(fragments)} chunks")
        else:
            fragments = [processed_data]
        
        # Use multipath transmission if enabled
        if self.use_multipath and len(fragments) > 1:
            return await self._send_multipath(fragments, destination, callbacks)
        else:
            # Single path transmission
            if self.domain_fronting:
                return await self._send_with_domain_fronting(fragments, destination, callbacks)
            else:
                return await self._send_direct(fragments, destination, callbacks)
    
    def fragment_data(self, data: bytes) -> List[bytes]:
        """
        Fragment data into smaller chunks to avoid pattern detection.
        
        Args:
            data: Data to fragment
            
        Returns:
            List of data fragments
        """
        # Simple fixed-size fragmentation
        fragments = []
        
        # Add a sequence number header to each fragment
        total_fragments = (len(data) + self.fragment_size - 1) // self.fragment_size
        
        for i in range(0, len(data), self.fragment_size):
            fragment_data = data[i:i+self.fragment_size]
            
            # Add header: [fragment_index (2 bytes)][total_fragments (2 bytes)]
            fragment_header = i // self.fragment_size
            header = fragment_header.to_bytes(2, byteorder='big')
            header += total_fragments.to_bytes(2, byteorder='big')
            
            fragments.append(header + fragment_data)
        
        # Randomize order to evade traffic analysis
        random.shuffle(fragments)
        
        return fragments
    
    def reassemble_fragments(self, fragments: List[bytes]) -> bytes:
        """
        Reassemble fragmented data.
        
        Args:
            fragments: List of data fragments
            
        Returns:
            Reassembled data
        """
        if not fragments:
            return b''
            
        # Parse headers to get total fragments and indexes
        indexed_fragments = []
        total_fragments = 0
        
        for fragment in fragments:
            if len(fragment) < 4:  # Minimum header size
                logger.warning("Received fragment with invalid size")
                continue
                
            # Extract header
            fragment_index = int.from_bytes(fragment[0:2], byteorder='big')
            total_fragments = int.from_bytes(fragment[2:4], byteorder='big')
            
            # Extract data (skip header)
            fragment_data = fragment[4:]
            
            indexed_fragments.append((fragment_index, fragment_data))
        
        # Sort fragments by index
        indexed_fragments.sort(key=lambda x: x[0])
        
        # Check for missing fragments
        received_indexes = {idx for idx, _ in indexed_fragments}
        expected_indexes = set(range(total_fragments))
        missing_indexes = expected_indexes - received_indexes
        
        if missing_indexes:
            logger.warning(f"Missing fragments: {missing_indexes}")
        
        # Reassemble data
        reassembled = b''.join(data for _, data in indexed_fragments)
        return reassembled
    
    async def _send_direct(self, fragments: List[bytes], destination: Tuple[str, int],
                          callbacks: Dict[str, Callable]) -> Optional[bytes]:
        """
        Send data directly to the destination.
        
        Args:
            fragments: Data fragments
            destination: Destination (host, port)
            callbacks: Callbacks for status updates
            
        Returns:
            Response data if successful, None otherwise
        """
        host, port = destination
        
        try:
            # Create connection
            reader, writer = await asyncio.open_connection(host, port)
            
            # Send all fragments
            for i, fragment in enumerate(fragments):
                writer.write(fragment)
                await writer.drain()
                
                if 'progress_callback' in callbacks:
                    callbacks['progress_callback'](i + 1, len(fragments))
            
            # Read response
            response_data = await reader.read(65536)  # Arbitrary large buffer
            
            # Clean up
            writer.close()
            await writer.wait_closed()
            
            return response_data
            
        except Exception as e:
            logger.error(f"Error in direct send: {str(e)}")
            if 'error_callback' in callbacks:
                callbacks['error_callback'](str(e))
            return None
    
    async def _send_with_domain_fronting(self, fragments: List[bytes], 
                                        destination: Tuple[str, int],
                                        callbacks: Dict[str, Callable]) -> Optional[bytes]:
        """
        Send data using domain fronting technique.
        
        This technique uses a different SNI (Server Name Indication) in the TLS connection
        than the actual Host header in the HTTP request, allowing to bypass some censors
        that only look at the SNI but not the actual HTTP headers.
        
        Args:
            fragments: Data fragments
            destination: Destination (host, port)
            callbacks: Callbacks for status updates
            
        Returns:
            Response data if successful, None otherwise
        """
        # Choose a random CDN provider
        cdn = random.choice(self.cdn_providers)
        fronting_domain = random.choice(cdn['fronting_domains'])
        
        # The real target host
        real_host, real_port = destination
        
        try:
            # Create SSL context
            ssl_context = ssl.create_default_context()
            
            # Connect to the fronting domain (what the censor sees)
            reader, writer = await asyncio.open_connection(
                cdn['host'], 443, ssl=ssl_context, server_hostname=fronting_domain
            )
            
            # Prepare HTTP request with actual Host header pointing to our real target
            http_headers = [
                f"POST /vpn_tunnel HTTP/1.1",
                f"Host: {real_host}",
                f"Connection: keep-alive",
                f"Content-Length: {sum(len(f) for f in fragments)}",
                "",
                ""
            ]
            
            # Send HTTP headers
            writer.write("\r\n".join(http_headers).encode())
            await writer.drain()
            
            # Send all fragments
            for i, fragment in enumerate(fragments):
                writer.write(fragment)
                await writer.drain()
                
                if 'progress_callback' in callbacks:
                    callbacks['progress_callback'](i + 1, len(fragments))
            
            # Read response
            response_data = await reader.read(65536)  # Arbitrary large buffer
            
            # Clean up
            writer.close()
            await writer.wait_closed()
            
            return response_data
            
        except Exception as e:
            logger.error(f"Error in domain fronting: {str(e)}")
            if 'error_callback' in callbacks:
                callbacks['error_callback'](str(e))
            return None
    
    async def _send_multipath(self, fragments: List[bytes], destination: Tuple[str, int],
                             callbacks: Dict[str, Callable]) -> Optional[bytes]:
        """
        Send data using multiple paths in parallel for redundancy and speed.
        
        Args:
            fragments: Data fragments
            destination: Destination (host, port)
            callbacks: Callbacks for status updates
            
        Returns:
            Response data if successful, None otherwise
        """
        # Divide fragments among paths
        path_count = min(self.max_paths, len(fragments))
        fragments_per_path = [[] for _ in range(path_count)]
        
        # Distribute fragments among paths
        for i, fragment in enumerate(fragments):
            path_index = i % path_count
            fragments_per_path[path_index].append(fragment)
        
        if 'multipath_callback' in callbacks:
            callbacks['multipath_callback'](path_count)
            
        logger.info(f"Using multipath transmission with {path_count} paths")
        
        # Create tasks for each path
        tasks = []
        
        for i, path_fragments in enumerate(fragments_per_path):
            if self.domain_fronting:
                task = asyncio.create_task(
                    self._send_with_domain_fronting(
                        path_fragments, destination, 
                        self._create_path_callbacks(callbacks, i, path_count)
                    )
                )
            else:
                task = asyncio.create_task(
                    self._send_direct(
                        path_fragments, destination,
                        self._create_path_callbacks(callbacks, i, path_count)
                    )
                )
            tasks.append(task)
        
        # Wait for all paths to complete or timeout
        try:
            done, pending = await asyncio.wait(
                tasks, timeout=self.path_timeout, return_when=asyncio.ALL_COMPLETED
            )
            
            # Cancel any pending tasks
            for task in pending:
                task.cancel()
            
            # Collect responses
            responses = []
            for task in done:
                try:
                    result = task.result()
                    if result:
                        responses.append(result)
                except Exception as e:
                    logger.error(f"Error in multipath task: {str(e)}")
            
            # Combine responses (in a real implementation, we would reassemble fragments here)
            if responses:
                # For simplicity, just return the first valid response
                return responses[0]
            else:
                logger.error("No successful responses from any path")
                return None
                
        except Exception as e:
            logger.error(f"Error in multipath transmission: {str(e)}")
            if 'error_callback' in callbacks:
                callbacks['error_callback'](str(e))
            return None
    
    def _create_path_callbacks(self, callbacks: Dict[str, Callable], 
                              path_index: int, path_count: int) -> Dict[str, Callable]:
        """
        Create path-specific callbacks to track progress of individual paths.
        
        Args:
            callbacks: Original callbacks
            path_index: Index of the current path
            path_count: Total number of paths
            
        Returns:
            Path-specific callbacks
        """
        path_callbacks = {}
        
        # Wrap each callback to include path information
        for name, callback in callbacks.items():
            if name == 'progress_callback':
                def progress_wrapper(current, total, path_idx=path_index, pc=path_count, cb=callback):
                    cb(current, total, path_idx, pc)
                path_callbacks[name] = progress_wrapper
            elif name == 'error_callback':
                def error_wrapper(error_msg, path_idx=path_index, pc=path_count, cb=callback):
                    cb(f"Path {path_idx+1}/{pc}: {error_msg}")
                path_callbacks[name] = error_wrapper
            else:
                path_callbacks[name] = callback
                
        return path_callbacks 