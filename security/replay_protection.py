"""
Replay Protection module for GFW evasion.

This module implements comprehensive replay protection to prevent attackers
from replaying previous connection attempts, which is a common technique
used by the GFW to confirm the presence of proxy services.
"""
import time
import logging
import threading
import hashlib
from typing import Dict, Set, List, Tuple, Optional, Any, Union
from collections import deque
import struct

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ReplayProtection:
    """
    Implements comprehensive replay protection using both nonce-based and
    timing-based mechanisms to prevent replay attacks.
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize the replay protection system.
        
        Args:
            config: Configuration options
        """
        self.config = config or {}
        
        # Nonce cache settings
        self.nonce_expiration = self.config.get('nonce_expiration_seconds', 3600)  # 1 hour by default
        self.max_nonces = self.config.get('max_nonces', 10000)  # Maximum nonces to store
        
        # Nonce cache structure: {nonce_hash: timestamp}
        self.nonce_cache = {}
        
        # Recent connections cache for timing-based replay protection
        self.connection_window = self.config.get('connection_window_seconds', 5)
        self.connection_history_size = self.config.get('connection_history_size', 1000)
        self.connection_history = deque(maxlen=self.connection_history_size)
        
        # Connection patterns to detect replay attacks
        self.replay_detection_window = self.config.get('replay_detection_window_seconds', 30)
        self.suspicious_repeat_threshold = self.config.get('suspicious_repeat_threshold', 3)
        
        # Lock for thread safety
        self.lock = threading.RLock()
        
        # Schedule cleanup task
        self.cleanup_interval = self.config.get('cleanup_interval_seconds', 300)  # 5 minutes
        self.last_cleanup_time = time.time()
        
        logger.info("Replay protection initialized")
    
    def generate_nonce(self) -> bytes:
        """
        Generate a secure random nonce for a new connection.
        
        Returns:
            Random nonce bytes
        """
        # Get 32 bytes of secure random data
        # In a real implementation, use a CSPRNG
        import os
        nonce = os.urandom(32)
        
        # Store this nonce in the cache
        nonce_hash = hashlib.sha256(nonce).hexdigest()
        with self.lock:
            self.nonce_cache[nonce_hash] = time.time()
            
        # Clean up old nonces if needed
        self._maybe_cleanup()
        
        return nonce
    
    def verify_nonce(self, nonce: bytes) -> bool:
        """
        Verify that a nonce has not been seen before and is valid.
        
        Args:
            nonce: The nonce to verify
            
        Returns:
            True if the nonce is valid, False otherwise
        """
        if not nonce:
            return False
            
        # Calculate hash for lookup
        nonce_hash = hashlib.sha256(nonce).hexdigest()
        
        with self.lock:
            # If nonce is in cache, it's a replay
            if nonce_hash in self.nonce_cache:
                logger.warning(f"Replay detected: duplicate nonce {nonce_hash[:8]}...")
                return False
                
            # Otherwise, store it and return success
            self.nonce_cache[nonce_hash] = time.time()
            
        # Clean up old nonces if needed
        self._maybe_cleanup()
        
        return True
    
    def check_replay_timing(self, client_addr: str, connection_data: Dict[str, Any]) -> bool:
        """
        Check for suspicious timing patterns that might indicate replay attacks.
        
        Args:
            client_addr: Client IP address
            connection_data: Connection metadata
            
        Returns:
            True if the connection passes timing checks, False if it looks like a replay
        """
        current_time = time.time()
        
        with self.lock:
            # Record this connection
            self.connection_history.append((current_time, client_addr, connection_data))
            
            # Look for suspicious repeat connections from the same client
            repeats = self._count_recent_connections(client_addr, current_time)
            
            # Apply thresholds for detection
            if repeats >= self.suspicious_repeat_threshold:
                logger.warning(f"Suspicious connection pattern: {repeats} connections from {client_addr} within {self.replay_detection_window}s")
                return False
        
        # Everything appears normal
        return True
    
    def _count_recent_connections(self, client_addr: str, current_time: float) -> int:
        """
        Count recent connections from a specific client.
        
        Args:
            client_addr: Client IP address
            current_time: Current timestamp
            
        Returns:
            Number of recent connections from this client
        """
        cutoff_time = current_time - self.replay_detection_window
        count = 0
        
        for ts, addr, _ in self.connection_history:
            if ts >= cutoff_time and addr == client_addr:
                count += 1
                
        return count
    
    def _maybe_cleanup(self) -> None:
        """Perform cleanup of expired nonces if it's time to do so."""
        current_time = time.time()
        
        # Only clean up on the specified interval
        if current_time - self.last_cleanup_time < self.cleanup_interval:
            return
            
        with self.lock:
            # Clean up expired nonces
            cutoff_time = current_time - self.nonce_expiration
            expired_nonces = [nonce for nonce, ts in self.nonce_cache.items() if ts < cutoff_time]
            
            for nonce in expired_nonces:
                del self.nonce_cache[nonce]
                
            # Also clean out old connection history entries that are beyond our windows
            oldest_needed = current_time - max(self.replay_detection_window, self.connection_window)
            
            # Since deque is FIFO, we can just check from the left until we hit a recent enough entry
            while self.connection_history and self.connection_history[0][0] < oldest_needed:
                self.connection_history.popleft()
                
            self.last_cleanup_time = current_time
            
            logger.debug(f"Cleaned up {len(expired_nonces)} expired nonces, {len(self.nonce_cache)} active")
    
    def add_nonce_to_packet(self, packet: bytes) -> bytes:
        """
        Add a nonce to an outgoing packet.
        
        Args:
            packet: Original packet data
            
        Returns:
            Packet with nonce added
        """
        nonce = self.generate_nonce()
        
        # Format: [1-byte nonce length][nonce][original packet]
        nonce_len = len(nonce)
        
        # Ensure nonce length can fit in a byte
        if nonce_len > 255:
            nonce = nonce[:255]
            nonce_len = 255
            
        modified_packet = bytes([nonce_len]) + nonce + packet
        return modified_packet
    
    def extract_nonce_from_packet(self, packet: bytes) -> Tuple[Optional[bytes], bytes]:
        """
        Extract a nonce from an incoming packet.
        
        Args:
            packet: Packet potentially containing a nonce
            
        Returns:
            Tuple of (nonce, remaining packet data) or (None, original packet)
        """
        if not packet or len(packet) < 2:  # Need at least length byte + 1 byte of nonce
            return None, packet
            
        # Get nonce length from first byte
        nonce_len = packet[0]
        
        # Validate nonce length
        if nonce_len == 0 or len(packet) < nonce_len + 1:
            return None, packet
            
        # Extract nonce and remaining packet
        nonce = packet[1:nonce_len+1]
        remaining_packet = packet[nonce_len+1:]
        
        return nonce, remaining_packet
    
    def verify_packet(self, packet: bytes, client_addr: str, 
                     conn_info: Dict[str, Any] = None) -> Tuple[bool, bytes]:
        """
        Verify that a packet is not a replay and extract the real packet data.
        
        Args:
            packet: The packet to verify
            client_addr: Client IP address
            conn_info: Additional connection information
            
        Returns:
            Tuple of (is_valid, packet_data)
            - is_valid: True if packet passes replay protection, False otherwise
            - packet_data: The packet data with nonce removed if present
        """
        # Extract and verify nonce
        nonce, remaining_packet = self.extract_nonce_from_packet(packet)
        
        if not nonce:
            # No nonce in packet
            logger.debug(f"No nonce found in packet from {client_addr}")
            return False, packet
            
        # Verify nonce hasn't been seen before
        if not self.verify_nonce(nonce):
            logger.warning(f"Replay detected: invalid nonce from {client_addr}")
            return False, remaining_packet
            
        # Verify timing patterns
        conn_data = conn_info or {}
        if not self.check_replay_timing(client_addr, conn_data):
            logger.warning(f"Replay detected: suspicious timing from {client_addr}")
            return False, remaining_packet
            
        # All checks passed
        return True, remaining_packet 