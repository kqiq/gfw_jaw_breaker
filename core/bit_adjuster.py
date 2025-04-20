"""
Entropy Management for GFW Evasion.

This module adjusts packet bit distributions to avoid detection by the Great Firewall (GFW),
which is known to detect fully encrypted traffic based on bit distribution patterns.
"""
import random
import logging
from typing import Union, List

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Define the bit distribution range that the GFW is known to flag
GFW_DETECTION_MIN = 3.4  # Lower bound of suspicious bit/byte ratio
GFW_DETECTION_MAX = 4.6  # Upper bound of suspicious bit/byte ratio

def count_bits(data: bytes) -> int:
    """Count the number of bits set to 1 in a byte array."""
    return sum(bin(byte).count('1') for byte in data)

def bits_per_byte(data: bytes) -> float:
    """Calculate the average number of bits set to 1 per byte."""
    if not data:
        return 0
    return count_bits(data) / len(data)

def is_in_detection_range(data: bytes) -> bool:
    """Check if the bit distribution is in the GFW detection range."""
    bpb = bits_per_byte(data)
    return GFW_DETECTION_MIN < bpb < GFW_DETECTION_MAX

def increase_packet_entropy(packet: bytes) -> bytes:
    """
    Increase the bit entropy of a packet to exceed the GFW detection threshold.
    
    This function aims to modify the packet so that it has more than 4.6 bits set per byte
    on average, which should help avoid GFW detection.
    """
    data = bytearray(packet)
    target_bits = int(GFW_DETECTION_MAX * len(data)) + 1
    current_bits = count_bits(data)
    
    if current_bits >= target_bits:
        return bytes(data)
    
    # Calculate how many more bits we need to set
    bits_to_add = target_bits - current_bits
    
    # Find positions where we can add bits (bytes with fewer than 8 bits set)
    eligible_positions = [(i, bin(b).count('1')) for i, b in enumerate(data) if bin(b).count('1') < 8]
    
    # Sort by number of bits already set (modify bytes with fewer bits first)
    eligible_positions.sort(key=lambda x: x[1])
    
    # Set bits until we reach the target or run out of positions
    bits_added = 0
    for pos, bits_set in eligible_positions:
        if bits_added >= bits_to_add:
            break
            
        # Get current byte value
        current_value = data[pos]
        
        # Find unset bits
        unset_bits = [i for i in range(8) if not (current_value & (1 << i))]
        
        # Randomly select an unset bit and set it
        if unset_bits:
            bit_to_set = random.choice(unset_bits)
            data[pos] |= (1 << bit_to_set)
            bits_added += 1
    
    return bytes(data)

def decrease_packet_entropy(packet: bytes) -> bytes:
    """
    Decrease the bit entropy of a packet to fall below the GFW detection threshold.
    
    This function aims to modify the packet so that it has fewer than 3.4 bits set per byte
    on average, which should help avoid GFW detection.
    """
    data = bytearray(packet)
    target_bits = int(GFW_DETECTION_MIN * len(data)) - 1
    current_bits = count_bits(data)
    
    if current_bits <= target_bits:
        return bytes(data)
    
    # Calculate how many bits we need to unset
    bits_to_remove = current_bits - target_bits
    
    # Find positions where we can remove bits (bytes with bits set)
    eligible_positions = [(i, bin(b).count('1')) for i, b in enumerate(data) if bin(b).count('1') > 0]
    
    # Sort by number of bits set (modify bytes with more bits first)
    eligible_positions.sort(key=lambda x: x[1], reverse=True)
    
    # Unset bits until we reach the target or run out of positions
    bits_removed = 0
    for pos, bits_set in eligible_positions:
        if bits_removed >= bits_to_remove:
            break
            
        # Get current byte value
        current_value = data[pos]
        
        # Find set bits
        set_bits = [i for i in range(8) if (current_value & (1 << i))]
        
        # Randomly select a set bit and unset it
        if set_bits:
            bit_to_unset = random.choice(set_bits)
            data[pos] &= ~(1 << bit_to_unset)
            bits_removed += 1
    
    return bytes(data)

def adjust_packet_entropy(packet: bytes) -> bytes:
    """
    Adjust packet bit distribution to avoid GFW detection.
    
    The GFW is known to flag packets with an average of 3.4-4.6 bits set per byte.
    This function modifies the packet to either have fewer than 3.4 bits or more than 4.6
    bits set per byte on average.
    
    Args:
        packet: The packet data to adjust
        
    Returns:
        Adjusted packet data
    """
    if not packet:
        return packet
        
    bpb = bits_per_byte(packet)
    
    # If we're in the detection range, adjust
    if GFW_DETECTION_MIN < bpb < GFW_DETECTION_MAX:
        logger.debug(f"Packet has {bpb:.2f} bits/byte, which is in the GFW detection range")
        
        if bpb > 4.0:
            # If closer to upper bound, increase to exceed 4.6
            return increase_packet_entropy(packet)
        else:
            # If closer to lower bound, decrease to fall below 3.4
            return decrease_packet_entropy(packet)
    
    # Already outside detection range
    logger.debug(f"Packet has {bpb:.2f} bits/byte, which is outside the GFW detection range")
    return packet

class BitAdjuster:
    """
    Provides methods to adjust packet bit distributions to avoid GFW detection.
    """
    
    def __init__(self, always_adjust_first_packet=True):
        """
        Initialize the BitAdjuster.
        
        Args:
            always_adjust_first_packet: Whether to always adjust the first packet of a connection
        """
        self.always_adjust_first_packet = always_adjust_first_packet
        self.connection_first_packets = set()
        
    def process_packet(self, packet: bytes, connection_id: str = None) -> bytes:
        """
        Process a packet to avoid GFW detection.
        
        Args:
            packet: The packet data to process
            connection_id: Unique identifier for the connection (if available)
            
        Returns:
            Processed packet data
        """
        is_first_packet = False
        
        # Check if this is the first packet of a connection
        if connection_id and connection_id not in self.connection_first_packets:
            is_first_packet = True
            self.connection_first_packets.add(connection_id)
        
        # Always adjust first packets, otherwise only adjust if in detection range
        if is_first_packet and self.always_adjust_first_packet:
            packet = adjust_packet_entropy(packet)
        elif is_in_detection_range(packet):
            packet = adjust_packet_entropy(packet)
            
        return packet 