"""
First Packet Optimizer for GFW Evasion.

This module ensures that the first packet of connections includes sufficient ASCII
characters to bypass the GFW's encryption detection heuristics and implements
packet size manipulation strategies to evade traffic analysis.
"""
import random
import logging
import os
from typing import Union, List, Tuple, Dict, Optional

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ASCII printable character range (excluding DEL)
ASCII_MIN = 0x20  # Space
ASCII_MAX = 0x7E  # Tilde

# Common packet lengths to avoid
SUSPICIOUS_LENGTHS = [32, 33, 86, 126, 130, 137, 215, 255, 256, 257, 1024, 1500]

# Safe ranges for packet size (outside common detection thresholds)
SAFE_SIZE_RANGES = [(60, 80), (150, 200), (300, 400), (600, 800), (1200, 1400)]

def is_printable_ascii(byte: int) -> bool:
    """Check if a byte is within the printable ASCII range."""
    return ASCII_MIN <= byte <= ASCII_MAX

def count_printable_ascii(data: bytes) -> int:
    """Count the number of printable ASCII characters in a byte array."""
    return sum(1 for byte in data if is_printable_ascii(byte))

def printable_ascii_ratio(data: bytes) -> float:
    """Calculate the ratio of printable ASCII characters in a byte array."""
    if not data:
        return 0
    return count_printable_ascii(data) / len(data)

def find_ascii_blocks(data: bytes, min_length: int = 21) -> List[Tuple[int, int]]:
    """
    Find blocks of contiguous printable ASCII characters.
    
    Args:
        data: The byte array to analyze
        min_length: Minimum length of ASCII block to find
        
    Returns:
        List of (start, end) tuples for blocks
    """
    blocks = []
    current_start = None
    
    for i, byte in enumerate(data):
        if is_printable_ascii(byte):
            if current_start is None:
                current_start = i
        else:
            if current_start is not None:
                if i - current_start >= min_length:
                    blocks.append((current_start, i))
                current_start = None
    
    # Check if we ended with an ASCII block
    if current_start is not None and len(data) - current_start >= min_length:
        blocks.append((current_start, len(data)))
    
    return blocks

def optimize_first_n_bytes(packet: bytes, n: int = 6) -> bytes:
    """
    Ensure the first N bytes of the packet are printable ASCII.
    
    Args:
        packet: The packet data to optimize
        n: Number of bytes to ensure are printable ASCII
        
    Returns:
        Optimized packet data
    """
    if len(packet) < n:
        return packet
    
    data = bytearray(packet)
    
    # Replace non-printable bytes with random printable ASCII
    for i in range(n):
        if not is_printable_ascii(data[i]):
            data[i] = random.randint(ASCII_MIN, ASCII_MAX)
    
    return bytes(data)

def ensure_ascii_block(packet: bytes, min_length: int = 21) -> bytes:
    """
    Ensure the packet contains at least one block of printable ASCII characters.
    
    Args:
        packet: The packet data to optimize
        min_length: Minimum length of ASCII block
        
    Returns:
        Optimized packet data
    """
    blocks = find_ascii_blocks(packet, min_length)
    
    if blocks:
        # Already has a sufficient ASCII block
        return packet
    
    data = bytearray(packet)
    
    # Find the best position to insert an ASCII block
    # Strategy: Look for the longest partial ASCII sequence
    best_start = 0
    best_length = 0
    
    current_start = None
    current_length = 0
    
    for i, byte in enumerate(data):
        if is_printable_ascii(byte):
            if current_start is None:
                current_start = i
            current_length += 1
        else:
            if current_start is not None:
                if current_length > best_length:
                    best_start = current_start
                    best_length = current_length
                current_start = None
                current_length = 0
    
    # Check if we ended with a partial ASCII block
    if current_start is not None and current_length > best_length:
        best_start = current_start
        best_length = current_length
    
    # Calculate how many more ASCII bytes we need
    bytes_needed = min_length - best_length
    
    if bytes_needed <= 0:
        # This shouldn't happen, but just in case
        return packet
    
    # Insert or replace bytes to create an ASCII block
    insert_pos = best_start + best_length
    
    # If we're inserting at the end, just append
    if insert_pos >= len(data):
        for _ in range(bytes_needed):
            data.append(random.randint(ASCII_MIN, ASCII_MAX))
    else:
        # Otherwise, replace existing bytes
        for i in range(bytes_needed):
            if insert_pos + i < len(data):
                data[insert_pos + i] = random.randint(ASCII_MIN, ASCII_MAX)
            else:
                data.append(random.randint(ASCII_MIN, ASCII_MAX))
    
    return bytes(data)

def increase_printable_ratio(packet: bytes, target_ratio: float = 0.51) -> bytes:
    """
    Increase the ratio of printable ASCII characters in a packet.
    
    Args:
        packet: The packet data to optimize
        target_ratio: Target ratio of printable ASCII characters
        
    Returns:
        Optimized packet data
    """
    current_ratio = printable_ascii_ratio(packet)
    
    if current_ratio >= target_ratio:
        return packet
    
    data = bytearray(packet)
    
    # Calculate how many bytes to convert
    printable_needed = int(target_ratio * len(data))
    current_printable = count_printable_ascii(data)
    bytes_to_convert = printable_needed - current_printable
    
    # Find non-printable bytes to convert
    non_printable_indices = [i for i, byte in enumerate(data) if not is_printable_ascii(byte)]
    
    # Shuffle to randomize which bytes we convert
    random.shuffle(non_printable_indices)
    
    # Convert bytes up to needed amount
    for i in range(min(bytes_to_convert, len(non_printable_indices))):
        pos = non_printable_indices[i]
        data[pos] = random.randint(ASCII_MIN, ASCII_MAX)
    
    return bytes(data)

def add_variable_padding(packet: bytes, min_pad: int = 8, max_pad: int = 32) -> bytes:
    """
    Add variable-length padding to a packet to avoid predictable packet lengths.
    
    Args:
        packet: The packet data to pad
        min_pad: Minimum padding bytes to add
        max_pad: Maximum padding bytes to add
        
    Returns:
        Padded packet data
    """
    # Determine random padding length
    pad_length = random.randint(min_pad, max_pad)
    
    # Create padding with random bytes
    padding = bytearray(random.getrandbits(8) for _ in range(pad_length))
    
    # Ensure padding contains some ASCII to maintain good ratio
    ascii_count = pad_length // 2
    for i in random.sample(range(pad_length), ascii_count):
        padding[i] = random.randint(ASCII_MIN, ASCII_MAX)
    
    # Append padding to packet
    return packet + bytes(padding)

def randomize_packet_size(packet: bytes) -> bytes:
    """
    Randomize packet size to avoid suspicious length patterns.
    
    Args:
        packet: The packet data to resize
        
    Returns:
        Resized packet data
    """
    # Check if current length is suspicious
    current_length = len(packet)
    
    # If we're already at a "safe" length, don't modify
    if not any(abs(current_length - bad_len) < 3 for bad_len in SUSPICIOUS_LENGTHS):
        # Still add small random padding to avoid exact pattern matching
        return add_variable_padding(packet, 1, 6)
    
    # Choose a random safe range
    min_size, max_size = random.choice(SAFE_SIZE_RANGES)
    
    # If packet is smaller than minimum, pad to safe range
    if current_length < min_size:
        pad_size = random.randint(min_size - current_length, max_size - current_length)
        return add_variable_padding(packet, pad_size, pad_size)
    
    # If packet is larger than maximum but less than next minimum, pad to next range
    if current_length > max_size:
        for min_next, max_next in SAFE_SIZE_RANGES:
            if min_next > current_length:
                pad_size = random.randint(min_next - current_length, max_next - current_length)
                return add_variable_padding(packet, pad_size, pad_size)
    
    # If packet is within safe range, add small random padding
    return add_variable_padding(packet, 1, 8)

def get_fragment_sizes(total_size: int, min_fragment: int = 40, max_fragments: int = 3) -> List[int]:
    """
    Calculate fragment sizes for packet fragmentation.
    
    Args:
        total_size: Total packet size to fragment
        min_fragment: Minimum fragment size
        max_fragments: Maximum number of fragments
        
    Returns:
        List of fragment sizes
    """
    if total_size <= min_fragment * 2:
        # Too small to fragment meaningfully
        return [total_size]
    
    # Determine number of fragments (2 to max_fragments)
    num_fragments = min(max_fragments, total_size // min_fragment)
    if num_fragments < 2:
        return [total_size]
    
    # Generate random fragment sizes
    fragments = []
    remaining = total_size
    
    for i in range(num_fragments - 1):
        # Ensure last fragment will be at least min_fragment
        max_size = remaining - min_fragment * (num_fragments - i - 1)
        # Ensure this fragment is at least min_fragment
        size = random.randint(min_fragment, max(min_fragment, max_size))
        fragments.append(size)
        remaining -= size
    
    # Add last fragment
    fragments.append(remaining)
    
    return fragments

def fragment_packet(packet: bytes) -> List[bytes]:
    """
    Fragment a packet into multiple smaller packets.
    
    Args:
        packet: The packet data to fragment
        
    Returns:
        List of fragmented packets
    """
    # Get fragment sizes
    sizes = get_fragment_sizes(len(packet))
    
    if len(sizes) == 1:
        return [packet]  # No fragmentation needed
    
    # Split packet according to fragment sizes
    fragments = []
    offset = 0
    
    for size in sizes:
        fragments.append(packet[offset:offset+size])
        offset += size
    
    return fragments

def optimize_first_packet(packet: bytes) -> bytes:
    """
    Apply ASCII character optimization to the first packet of a connection.
    
    This implements multiple strategies to bypass GFW detection:
    1. Ensure the first 6+ bytes are printable ASCII
    2. Ensure >50% of the packet consists of printable ASCII
    3. Include a sequence of 21+ contiguous printable ASCII characters
    4. Randomize packet size to avoid suspicious patterns
    5. Add variable-length padding
    
    Args:
        packet: The packet data to optimize
        
    Returns:
        Optimized packet data
    """
    if not packet:
        return packet
    
    # Strategy 1: Make the first 6+ bytes printable ASCII
    packet = optimize_first_n_bytes(packet, 6)
    
    # Strategy 2: Ensure >50% printable ASCII
    if printable_ascii_ratio(packet) < 0.5:
        packet = increase_printable_ratio(packet, 0.51)
    
    # Strategy 3: Ensure at least one block of 21+ contiguous ASCII chars
    if not find_ascii_blocks(packet, 21):
        packet = ensure_ascii_block(packet, 21)
    
    # Strategy 4: Randomize packet size to avoid suspicious patterns
    packet = randomize_packet_size(packet)
    
    # Strategy 5: Add variable-length padding
    packet = add_variable_padding(packet)
    
    return packet

class FirstPacketOptimizer:
    """
    Optimizes the first packet of connections to bypass GFW detection.
    """
    
    def __init__(self, config: Dict[str, any] = None):
        """Initialize the FirstPacketOptimizer."""
        self.config = config or {}
        self.connection_first_packets = set()
        self.enable_fragmentation = self.config.get('enable_packet_fragmentation', True)
        self.variable_padding = self.config.get('enable_variable_padding', True)
        self.randomize_sizes = self.config.get('randomize_packet_sizes', True)
        self.fragmentation_probability = self.config.get('fragmentation_probability', 0.7)
        self.max_fragments = self.config.get('max_fragments', 3)
        
        # Store fragments for connections
        self.connection_fragments = {}
    
    def process_packet(self, packet: bytes, connection_id: str = None) -> Union[bytes, List[bytes]]:
        """
        Process a packet, optimizing it if it's the first in a connection.
        
        Args:
            packet: The packet data to process
            connection_id: Unique identifier for the connection (if available)
            
        Returns:
            Processed packet data or list of packet fragments
        """
        if not connection_id:
            # If we can't track connections, assume it could be a first packet
            optimized = optimize_first_packet(packet)
            return self._maybe_fragment(optimized, None)
        
        # Check if this is the first packet of a connection
        if connection_id not in self.connection_first_packets:
            self.connection_first_packets.add(connection_id)
            optimized = optimize_first_packet(packet)
            return self._maybe_fragment(optimized, connection_id)
        
        # Check if this is a queued fragment from a previous fragmentation
        if connection_id in self.connection_fragments and self.connection_fragments[connection_id]:
            next_fragment = self.connection_fragments[connection_id].pop(0)
            
            # If we've sent all fragments, clean up
            if not self.connection_fragments[connection_id]:
                del self.connection_fragments[connection_id]
                
            return next_fragment
            
        # Not a first packet, return unchanged
        return packet
        
    def _maybe_fragment(self, packet: bytes, connection_id: Optional[str]) -> Union[bytes, List[bytes]]:
        """
        Possibly fragment a packet based on configuration.
        
        Args:
            packet: The packet to maybe fragment
            connection_id: Connection identifier
            
        Returns:
            Either the original packet or the first fragment of a fragmented packet
        """
        if not self.enable_fragmentation or random.random() > self.fragmentation_probability:
            return packet
            
        # Fragment the packet
        fragments = fragment_packet(packet)
        
        if len(fragments) <= 1:
            # No fragmentation occurred
            return packet
            
        # If we have a connection ID, store remaining fragments for later
        if connection_id:
            self.connection_fragments[connection_id] = fragments[1:]
            logger.debug(f"Fragmented packet into {len(fragments)} parts for connection {connection_id}")
            
            # Return first fragment
            return fragments[0]
        else:
            # Without connection ID, we can't properly fragment, so return original
            return packet
            
    def get_queued_fragments(self, connection_id: str) -> List[bytes]:
        """
        Get any queued fragments for a connection.
        
        Args:
            connection_id: Connection identifier
            
        Returns:
            List of remaining fragments (or empty list if none)
        """
        if connection_id in self.connection_fragments:
            fragments = self.connection_fragments.pop(connection_id)
            return fragments
        return [] 