"""
GFW Evasion Integration module.

This module integrates all the GFW evasion techniques into a single component
that can be used by the VPN engine.
"""
import logging
import time
import asyncio
import random
from typing import Dict, Any, Optional, Tuple, List, Set

from core.bit_adjuster import BitAdjuster
from protocols.first_packet_optimizer import FirstPacketOptimizer
from obfuscation.header_mimicry import HeaderMimicry
from security.probe_detector import ProbeDetector
from security.replay_protection import ReplayProtection
from security.tcp_normalizer import TCPNormalizer
from overlay.domain_fronting import DomainFrontingManager

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class GFWEvasionManager:
    """
    Manages GFW evasion techniques and applies them to network traffic.
    
    This class integrates multiple GFW evasion techniques:
    1. Bit distribution adjustment to avoid statistical analysis
    2. ASCII optimization for first packets
    3. Protocol header mimicry to look like legitimate traffic
    4. Active probe detection and response
    5. Dynamic domain fronting
    6. Packet fragmentation and size randomization
    7. Replay attack protection
    8. TCP behavior normalization
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize the GFW evasion manager.
        
        Args:
            config: Configuration options
        """
        self.config = config or {}
        
        # Flag to enable/disable GFW evasion
        self.enabled = self.config.get('gfw_evasion_enabled', True)
        
        # Initialize components
        self.bit_adjuster = BitAdjuster(
            always_adjust_first_packet=self.config.get('always_adjust_first_packet', True)
        )
        
        self.first_packet_optimizer = FirstPacketOptimizer(self.config)
        
        self.header_mimicry = HeaderMimicry(
            default_protocol=self.config.get('default_header_mimicry', 'tls')
        )
        
        self.probe_detector = ProbeDetector(self.config)
        self.replay_protection = ReplayProtection(self.config)
        self.tcp_normalizer = TCPNormalizer(self.config)
        
        self.domain_fronting = DomainFrontingManager(self.config)
        
        # Adaptive defense
        self.adaptive_mode = self.config.get('adaptive_defense_mode', True)
        self.defense_levels = {
            'normal': {
                'packet_fragmentation': 0.3,
                'header_mimicry': True,
                'bit_adjustment': True,
                'first_packet_optimization': True
            },
            'enhanced': {
                'packet_fragmentation': 0.7,
                'header_mimicry': True,
                'bit_adjustment': True,
                'first_packet_optimization': True
            },
            'paranoid': {
                'packet_fragmentation': 0.9,
                'header_mimicry': True,
                'bit_adjustment': True,
                'first_packet_optimization': True,
                'random_padding': True
            }
        }
        self.current_defense_level = 'normal'
        
        # Monitoring and metrics
        self.probe_detection_threshold = self.config.get('probe_detection_threshold', 3)
        
        # Statistics
        self.packets_processed = 0
        self.connections_handled = 0
        self.probes_detected = 0
        self.domains_rotated = 0
        self.active_connections = 0
        self.fragments_sent = 0
        self.replay_attacks_blocked = 0
        
        # Circuit breaker pattern for rapid defense level escalation
        self.circuit_breaker_probes = 0
        self.circuit_breaker_window = self.config.get('circuit_breaker_window_seconds', 60)
        self.circuit_breaker_threshold = self.config.get('circuit_breaker_threshold', 5)
        self.circuit_breaker_last_triggered = 0
        
        # Register for probe alerts
        self.probe_detector.register_alert_callback(self._on_probe_detected)
        
        logger.info("GFW Evasion Manager initialized")
        
    async def initialize(self) -> None:
        """Initialize all components that require async initialization."""
        if self.enabled:
            await self.domain_fronting.initialize()
        
    async def close(self) -> None:
        """Close and clean up resources."""
        if self.domain_fronting:
            await self.domain_fronting.close()
    
    def new_connection(self, conn_info: Dict[str, Any]) -> None:
        """
        Register a new connection.
        
        Args:
            conn_info: Connection information including remote_addr and metadata
        """
        if not self.enabled:
            return
            
        self.connections_handled += 1
        self.active_connections += 1
        
        # Normalize TCP behavior
        writer = conn_info.get('writer')
        if writer:
            asyncio.create_task(self.tcp_normalizer.normalize_writer(writer))
        
        # Register with probe detector for timing analysis
        self.probe_detector.connection_opened(conn_info)
    
    def connection_closed(self, conn_info: Dict[str, Any]) -> None:
        """
        Register a closed connection.
        
        Args:
            conn_info: Connection information
        """
        if not self.enabled:
            return
            
        self.active_connections -= 1 if self.active_connections > 0 else 0
    
    async def process_outgoing_packet(self, data: bytes, conn_info: Dict[str, Any]) -> bytes:
        """
        Process an outgoing packet to evade GFW detection.
        
        Args:
            data: Packet data
            conn_info: Connection information
            
        Returns:
            Modified packet data
        """
        if not self.enabled or not data:
            return data
            
        self.packets_processed += 1
        connection_id = conn_info.get('connection_id')
        
        # Apply current defense level settings
        defense = self.defense_levels[self.current_defense_level]
        
        # Add replay protection nonce to outgoing packets
        if hasattr(self, 'replay_protection'):
            data = self.replay_protection.add_nonce_to_packet(data)
        
        # Process the packet through our evasion components
        # Order is important:
        
        # 1. Apply protocol mimicry first (for first packets)
        if defense.get('header_mimicry', True):
            data = self.header_mimicry.process_packet(data, connection_id)
        
        # 2. Apply ASCII optimization (for first packets)
        if defense.get('first_packet_optimization', True):
            # This may return a list of fragments for the first packet
            result = self.first_packet_optimizer.process_packet(data, connection_id)
            
            # Handle fragmentation
            if isinstance(result, list):
                self.fragments_sent += len(result) - 1
                # Return first fragment, others will be sent later
                data = result[0]
            else:
                data = result
        
        # 3. Finally adjust bit entropy
        if defense.get('bit_adjustment', True):
            data = self.bit_adjuster.process_packet(data, connection_id)
        
        # Apply TCP timing normalization
        await self.tcp_normalizer.apply_response_delay()
        
        return data
    
    async def process_incoming_packet(self, data: bytes, conn_info: Dict[str, Any]) -> Tuple[bool, Optional[bytes]]:
        """
        Process an incoming packet and check for GFW probes.
        
        Args:
            data: Packet data
            conn_info: Connection information
            
        Returns:
            Tuple of (should_continue, response_data):
            - should_continue: Whether to continue processing this packet
            - response_data: Optional response data to send back
        """
        if not self.enabled or not data:
            return True, None
            
        # First check for replay attack using replay protection
        remote_addr = conn_info.get('remote_addr')
        if remote_addr and hasattr(self, 'replay_protection'):
            is_valid, clean_data = self.replay_protection.verify_packet(data, remote_addr, conn_info)
            if not is_valid:
                logger.warning(f"Replay attack detected from {remote_addr}")
                self.replay_attacks_blocked += 1
                return False, None
            
            # Use the data with nonce removed for further processing
            data = clean_data
        
        # Check if this is a GFW probe attempt
        is_probe, probe_type = self.probe_detector.is_probe_attempt(data, conn_info)
        if is_probe:
            self.probes_detected += 1
            
            # Update circuit breaker
            self._update_circuit_breaker()
            
            logger.warning(f"Detected {probe_type or 'unknown'} probe from {conn_info.get('remote_addr')}")
            return self.probe_detector.handle_probe(data, conn_info, probe_type)
            
        return True, None
    
    async def apply_domain_fronting(self, target_url: str) -> Tuple[str, Dict[str, str]]:
        """
        Apply domain fronting to a target URL.
        
        Args:
            target_url: Original target URL
            
        Returns:
            Tuple of (fronted_url, headers)
        """
        if not self.enabled:
            # Return the original URL and empty headers if disabled
            return target_url, {}
            
        return await self.domain_fronting.apply_domain_fronting(target_url)
    
    async def rotate_domain(self) -> None:
        """Rotate to a different domain for fronting."""
        if not self.enabled:
            return
            
        try:
            await self.domain_fronting.rotate_domain()
            self.domains_rotated += 1
        except Exception as e:
            logger.error(f"Error rotating domain: {str(e)}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about GFW evasion activities."""
        return {
            'enabled': self.enabled,
            'defense_level': self.current_defense_level,
            'packets_processed': self.packets_processed,
            'connections_handled': self.connections_handled,
            'probes_detected': self.probes_detected,
            'domains_rotated': self.domains_rotated,
            'active_connections': self.active_connections,
            'fragments_sent': self.fragments_sent,
            'replay_attacks_blocked': self.replay_attacks_blocked,
            'current_domain': self.domain_fronting.current_domain,
        }
    
    def set_enabled(self, enabled: bool) -> None:
        """Enable or disable GFW evasion."""
        self.enabled = enabled
        logger.info(f"GFW evasion {'enabled' if enabled else 'disabled'}")
    
    def _on_probe_detected(self, remote_addr: str, probe_info: Dict[str, Any]) -> None:
        """
        Callback for when a probe is detected.
        
        Args:
            remote_addr: Remote address of the probe
            probe_info: Information about the probe
        """
        # Increase defense level if we're receiving multiple probes
        if self.adaptive_mode:
            self._update_defense_level()
    
    def _update_defense_level(self) -> None:
        """Update the defense level based on the current threat level."""
        if not self.adaptive_mode:
            return
            
        current_time = time.time()
        
        # Check if circuit breaker has been triggered
        if current_time - self.circuit_breaker_last_triggered < self.circuit_breaker_window * 3:
            # We're in heightened defense mode due to circuit breaker
            if self.current_defense_level != 'paranoid':
                self.current_defense_level = 'paranoid'
                logger.warning("Defense level escalated to PARANOID due to circuit breaker")
            return
            
        # Otherwise base it on recent probe count
        if self.probes_detected > 10:
            if self.current_defense_level != 'paranoid':
                self.current_defense_level = 'paranoid'
                logger.warning("Defense level escalated to PARANOID due to high probe count")
        elif self.probes_detected > 5:
            if self.current_defense_level != 'enhanced' and self.current_defense_level != 'paranoid':
                self.current_defense_level = 'enhanced'
                logger.info("Defense level escalated to ENHANCED due to moderate probe count")
        else:
            if self.current_defense_level != 'normal':
                self.current_defense_level = 'normal'
                logger.info("Defense level restored to NORMAL due to low probe activity")
    
    def _update_circuit_breaker(self) -> None:
        """Update the circuit breaker state when a probe is detected."""
        current_time = time.time()
        
        # Reset circuit breaker counter if outside window
        if current_time - self.circuit_breaker_last_triggered > self.circuit_breaker_window:
            self.circuit_breaker_probes = 1
        else:
            self.circuit_breaker_probes += 1
            
        # Check if we should trip the circuit breaker
        if self.circuit_breaker_probes >= self.circuit_breaker_threshold:
            # Circuit breaker tripped - immediate defense escalation
            self.circuit_breaker_last_triggered = current_time
            self.circuit_breaker_probes = 0
            
            # Immediate actions:
            # 1. Escalate to paranoid mode
            self.current_defense_level = 'paranoid'
            # 2. Rotate domain
            asyncio.create_task(self.rotate_domain())
            # 3. Randomize TCP behavior
            self.tcp_normalizer.randomize_behavior()
            
            logger.warning("Circuit breaker triggered - Taking immediate defensive actions")
    
    async def get_queued_fragments(self, connection_id: str) -> List[bytes]:
        """
        Get any queued fragments for a connection.
        
        Args:
            connection_id: Connection identifier
            
        Returns:
            List of queued fragments to send
        """
        if hasattr(self.first_packet_optimizer, 'get_queued_fragments'):
            return self.first_packet_optimizer.get_queued_fragments(connection_id)
        return [] 