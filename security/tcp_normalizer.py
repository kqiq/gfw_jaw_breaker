"""
TCP Behavior Normalizer for GFW evasion.

This module normalizes TCP behavior to prevent fingerprinting by the GFW,
including window size randomization, TTL normalization, and TCP options management.
"""
import logging
import random
import socket
import asyncio
from typing import Dict, Any, Optional, Tuple, List, Set, Union

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Common TCP window sizes for popular browsers and applications
COMMON_WINDOW_SIZES = [
    16384,  # Chrome default
    65535,  # Maximum typical window
    29200,  # Firefox default
    8192,   # Common default
    32768,  # Safari default
    14600,  # Edge default
]

# Common TTL values by OS
COMMON_TTLS = {
    'windows': [128, 127, 126],  # Windows typically uses 128
    'linux': [64, 63, 62],        # Linux typically uses 64
    'macos': [64, 63, 62],        # MacOS typically uses 64
    'ios': [64, 63],              # iOS typically uses 64
    'android': [64, 63, 62],      # Android typically uses 64
}

class TCPNormalizer:
    """
    Normalizes TCP connection behavior to avoid fingerprinting by the GFW.
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize the TCP normalizer.
        
        Args:
            config: Configuration options
        """
        self.config = config or {}
        
        # TCP window size settings
        self.normalize_window_size = self.config.get('normalize_window_size', True)
        self.random_window_size = self.config.get('random_window_size', True)
        self.window_size = self.config.get('default_window_size', 65535)
        
        # TCP TTL settings
        self.normalize_ttl = self.config.get('normalize_ttl', True)
        self.ttl_os = self.config.get('ttl_os', 'windows')  # Mimic windows by default
        self.ttl_value = self.config.get('ttl_value', None)  # If None, will select from OS defaults
        
        # TCP options
        self.normalize_tcp_options = self.config.get('normalize_tcp_options', True)
        self.include_timestamps = self.config.get('include_timestamps', True)
        self.include_window_scaling = self.config.get('include_window_scaling', True)
        
        # Response timing normalization
        self.normalize_response_timing = self.config.get('normalize_response_timing', True)
        self.min_response_delay = self.config.get('min_response_delay', 0.05)
        self.max_response_delay = self.config.get('max_response_delay', 0.2)
        
        # Default connection class for different operating systems
        self.os_profile = self.config.get('os_profile', 'windows')
        
        logger.info(f"TCP Normalizer initialized with OS profile: {self.os_profile}")
    
    def get_normalized_window_size(self) -> int:
        """
        Get a normalized TCP window size that mimics legitimate applications.
        
        Returns:
            Window size value
        """
        if not self.normalize_window_size:
            return self.window_size
            
        if self.random_window_size:
            # Get a random common window size to avoid fingerprinting
            return random.choice(COMMON_WINDOW_SIZES)
        else:
            return self.window_size
    
    def get_normalized_ttl(self) -> int:
        """
        Get a normalized TTL value that mimics the selected OS.
        
        Returns:
            TTL value
        """
        if not self.normalize_ttl:
            return 64  # Default TTL
            
        if self.ttl_value:
            return self.ttl_value
            
        # Get TTL values for the selected OS profile
        ttl_values = COMMON_TTLS.get(self.os_profile.lower(), COMMON_TTLS['windows'])
        
        # Add slight randomness to TTL to avoid exact matching
        return random.choice(ttl_values)
    
    def normalize_socket(self, sock: socket.socket) -> None:
        """
        Apply TCP normalizations to a socket.
        
        Args:
            sock: Socket to normalize
        """
        if not sock:
            return
            
        try:
            # Set normalized window size
            if self.normalize_window_size:
                window_size = self.get_normalized_window_size()
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, window_size)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, window_size)
                
            # Set normalized TTL
            if self.normalize_ttl:
                ttl = self.get_normalized_ttl()
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
                
            # Configure TCP options if supported by platform
            if self.normalize_tcp_options:
                self._set_tcp_options(sock)
                
        except Exception as e:
            logger.warning(f"Error normalizing socket: {str(e)}")
    
    def _set_tcp_options(self, sock: socket.socket) -> None:
        """
        Set TCP options to mimic legitimate browsers.
        
        Args:
            sock: Socket to configure
        """
        try:
            # Enable TCP keepalive
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            
            # Platform-specific TCP options
            if hasattr(socket, 'TCP_NODELAY'):
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                
            # Some platforms support these advanced options
            try:
                if self.include_window_scaling and hasattr(socket, 'TCP_WINDOW_CLAMP'):
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_WINDOW_CLAMP, 
                                   self.get_normalized_window_size())
            except (AttributeError, OSError):
                pass
                
        except Exception as e:
            logger.debug(f"Error setting TCP options: {str(e)}")
    
    async def normalize_writer(self, writer: asyncio.StreamWriter) -> None:
        """
        Apply TCP normalizations to an asyncio StreamWriter.
        
        Args:
            writer: StreamWriter to normalize
        """
        if not writer:
            return
            
        try:
            sock = writer.get_extra_info('socket')
            if sock:
                self.normalize_socket(sock)
        except Exception as e:
            logger.warning(f"Error normalizing StreamWriter: {str(e)}")
    
    async def apply_response_delay(self) -> None:
        """
        Apply a normalized response delay to mimic legitimate services.
        """
        if not self.normalize_response_timing:
            return
            
        # Apply a randomized delay within configured bounds
        delay = random.uniform(self.min_response_delay, self.max_response_delay)
        await asyncio.sleep(delay)
    
    def get_connection_info(self, writer: asyncio.StreamWriter) -> Dict[str, Any]:
        """
        Get normalized connection information for logging and analysis.
        
        Args:
            writer: The connection's StreamWriter
            
        Returns:
            Dictionary of connection information
        """
        sock = writer.get_extra_info('socket')
        peer = writer.get_extra_info('peername')
        
        info = {
            'remote_addr': peer[0] if peer else None,
            'remote_port': peer[1] if peer and len(peer) > 1 else None,
            'local_addr': writer.get_extra_info('sockname', (None, None))[0],
            'tcp_options': {}
        }
        
        if sock:
            # Get actual TCP options that we've set
            try:
                info['tcp_options']['window_size'] = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
                info['tcp_options']['ttl'] = sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
                info['tcp_options']['nodelay'] = sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY)
            except Exception:
                pass
        
        return info
    
    async def create_normalized_connection(self, host: str, port: int, 
                                         ssl: Union[bool, object] = None) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """
        Create a new connection with normalized TCP behavior.
        
        Args:
            host: Target hostname or IP
            port: Target port
            ssl: SSL context or boolean
            
        Returns:
            Tuple of (StreamReader, StreamWriter)
        """
        # Create the connection
        reader, writer = await asyncio.open_connection(host, port, ssl=ssl)
        
        # Apply normalizations
        await self.normalize_writer(writer)
        
        return reader, writer
    
    def get_normalized_tcp_options(self) -> Dict[str, Any]:
        """
        Get normalized TCP options for connections.
        
        Returns:
            Dictionary of TCP options
        """
        return {
            'window_size': self.get_normalized_window_size(),
            'ttl': self.get_normalized_ttl(),
            'nodelay': 1 if self.os_profile.lower() in ['windows', 'macos'] else 0,
        }
    
    def randomize_behavior(self) -> None:
        """
        Randomize the TCP behavior to avoid pattern recognition.
        """
        if self.random_window_size:
            self.window_size = random.choice(COMMON_WINDOW_SIZES)
            
        # Randomly select an OS profile
        os_options = list(COMMON_TTLS.keys())
        self.os_profile = random.choice(os_options)
        
        # Randomize TCP options
        self.include_timestamps = random.choice([True, False])
        
        logger.debug(f"Randomized TCP behavior: window={self.window_size}, OS={self.os_profile}")
    
    async def apply_error_normalization(self, writer: asyncio.StreamWriter, 
                                      error_type: str = 'generic') -> None:
        """
        Apply consistent error handling behavior to prevent fingerprinting.
        
        Args:
            writer: StreamWriter to use for the response
            error_type: Type of error to mimic
        """
        # Normalize behavior for errors to prevent fingerprinting
        # For all error types, we want the same outward behavior
        
        # 1. Add a consistent delay
        await self.apply_response_delay()
        
        # 2. If configured to read forever, don't close the connection
        if self.config.get('read_forever_on_error', False):
            # Keep connection open but don't respond
            return
            
        # 3. Otherwise, for most errors, just close the connection without responding
        try:
            # Close the connection cleanly
            writer.close()
            await writer.wait_closed()
        except Exception:
            # Ignore any errors during close
            pass 