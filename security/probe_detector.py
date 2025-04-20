"""
Active Probe Detection and Defense module for GFW evasion.

This module detects and responds to GFW's active probing attempts, which are used
to confirm the presence of VPN and proxy services after passive detection.
"""
import logging
import time
import json
import socket
import asyncio
import random
from typing import Dict, Any, List, Tuple, Optional, Set, Callable

from security.replay_protection import ReplayProtection

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# GFW Probe Types based on research papers
# R1-R5: Standard probe types that expect a response
# NR1-NR2: Non-response probe types that detect presence by absence of response
PROBE_TYPES = {
    "R1": {
        "name": "TLS Client Hello probe",
        "pattern": bytes.fromhex("160303"),  # TLS Handshake
        "stage": 1,  # First stage probe
        "description": "Typical TLS handshake probe to test for TLS proxy response",
    },
    "R2": {
        "name": "HTTP request probe",
        "pattern": bytes.fromhex("474554202f20485454502f312e310d0a"),  # GET / HTTP/1.1
        "stage": 1,  # First stage probe
        "description": "HTTP request probe to test for web proxy response",
    },
    "R3": {
        "name": "Shadowsocks/V2Ray probe",
        "pattern": bytes.fromhex("05010001"),  # SOCKS5 connect
        "stage": 2,  # Second stage probe, more specific
        "description": "Probe targeting Shadowsocks or V2Ray protocol specifics",
    },
    "R4": {
        "name": "SSH probe",
        "pattern": bytes.fromhex("5353482d322e302d"),  # SSH-2.0-
        "stage": 1,  # First stage probe
        "description": "SSH handshake probe to test for SSH tunneling",
    },
    "R5": {
        "name": "Custom VPN protocol probe",
        "pattern": bytes.fromhex("1703030000"),  # TLS 1.2 empty record
        "stage": 2,  # Second stage probe, more specific
        "description": "Targets custom VPN protocols with TLS characteristics",
    },
    "NR1": {
        "name": "Trojan probe",
        "pattern": bytes.fromhex("170303"),  # TLS 1.2 record
        "stage": 3,  # Third stage probe, very specific
        "requires_previous": ["R1", "R5"],  # Must have seen these earlier probes
        "description": "Specifically targets Trojan protocol with invalid payload",
        "response": "none",  # Don't respond
    },
    "NR2": {
        "name": "Advanced pattern probe",
        "pattern": b"\x00\x00\x00\x00\x00\x00\x00\x00",  # 8 null bytes
        "stage": 3,  # Third stage probe, very specific
        "requires_previous": ["R1", "R3"],  # Must have seen these earlier probes
        "description": "Advanced probe with unusual byte patterns",
        "response": "none",  # Don't respond
    },
}

class ProbeDetector:
    """
    Detects and responds to GFW active probing attempts.
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize the probe detector.
        
        Args:
            config: Configuration options
        """
        self.config = config or {}
        self.probe_signatures = self._load_probe_signatures()
        self.suspicious_ips = set()
        self.probe_history = {}
        self.connection_start_times = {}
        self.last_cleanup_time = time.time()
        
        # IP address to probe type history
        self.ip_probe_stages = {}
        
        # Response strategy
        self.default_response_strategy = self.config.get("probe_response", "mislead")
        
        # Initialize replay protection
        self.replay_protection = ReplayProtection(self.config)
        
        # Response behavior - reads from config or uses defaults
        self.consistent_response_time = self.config.get("consistent_response_time", True)
        self.minimum_response_delay = self.config.get("minimum_response_delay", 0.1)
        self.maximum_response_delay = self.config.get("maximum_response_delay", 0.3)
        self.staged_response = self.config.get("staged_response", True)
        
        # Success/error response consistency
        self.normalize_errors = self.config.get("normalize_errors", True)
        self.read_forever_on_error = self.config.get("read_forever_on_error", False)
        
        # TCP behavior normalization
        self.normalize_tcp_window = self.config.get("normalize_tcp_window", True)
        self.normal_window_size = self.config.get("normal_window_size", 65535)
        
        # Probe alert callbacks
        self.alert_callbacks = []
        
        # Setup misleading responses for different protocols
        self.misleading_responses = {
            "tls": self._generate_tls_error_response,
            "http": self._generate_http_error_response,
            "ssh": self._generate_ssh_error_response,
            "socks": self._generate_socks_error_response,
        }
        
        # Configure TCP options for responses
        self.tcp_options = {}
        if self.normalize_tcp_window:
            self.tcp_options["window_size"] = self.normal_window_size
        
        logger.info("Probe detector initialized")
    
    def _load_probe_signatures(self) -> Dict[str, Dict[str, Any]]:
        """
        Load probe signatures from configuration or use defaults.
        
        Returns:
            Dictionary of probe signatures
        """
        signatures = self.config.get("probe_signatures", {})
        
        if not signatures:
            signatures = PROBE_TYPES
            logger.info(f"Using {len(signatures)} built-in probe signatures")
        else:
            logger.info(f"Loaded {len(signatures)} custom probe signatures")
            
        return signatures
    
    def register_alert_callback(self, callback: Callable[[str, Dict[str, Any]], None]) -> None:
        """
        Register a callback to be notified when probes are detected.
        
        Args:
            callback: Function to call when a probe is detected
                     Takes (ip_address, probe_info) as arguments
        """
        self.alert_callbacks.append(callback)
    
    def connection_opened(self, conn_info: Dict[str, Any]) -> None:
        """
        Record a new connection for timing analysis.
        
        Args:
            conn_info: Connection information including remote_addr and other metadata
        """
        remote_addr = conn_info.get("remote_addr")
        if not remote_addr:
            return
            
        # Record connection start time
        self.connection_start_times[remote_addr] = time.time()
        
        # Check if this IP is already suspicious
        if remote_addr in self.suspicious_ips:
            logger.warning(f"New connection from previously suspicious IP: {remote_addr}")
            
        # Initialize probe stage history for this IP if needed
        if remote_addr not in self.ip_probe_stages:
            self.ip_probe_stages[remote_addr] = {
                "stages_seen": set(),
                "probe_types_seen": set(),
                "last_probe_time": 0,
                "total_probes": 0
            }
    
    def _check_tcp_options(self, conn_info: Dict[str, Any]) -> bool:
        """
        Check TCP options for probe signatures.
        
        Args:
            conn_info: Connection information including TCP options
            
        Returns:
            True if connection matches known probe TCP options
        """
        if "tcp_options" not in conn_info:
            return False
            
        tcp_opts = conn_info.get("tcp_options", {})
        
        # Common GFW probe window sizes
        suspicious_window_sizes = [65535, 16384, 8192, 4096, 2048]
        
        # Check window size - GFW probes often use specific window sizes
        window_size = tcp_opts.get("window_size")
        if window_size in suspicious_window_sizes:
            return True
            
        # Check TCP flags - SYN-ACK packets with unusual flags can indicate probing
        flags = tcp_opts.get("flags", 0)
        if flags & 0x02 and flags & 0x10 and flags & 0x08:  # SYN + ACK + PSH
            return True
            
        # Check TTL - GFW probes often have specific TTL values
        ttl = tcp_opts.get("ttl")
        if ttl and ttl < 32:  # Suspiciously low TTL
            return True
            
        return False
    
    def _check_timing_pattern(self, conn_info: Dict[str, Any]) -> bool:
        """
        Check for suspicious timing patterns.
        
        Args:
            conn_info: Connection information
            
        Returns:
            True if connection exhibits suspicious timing
        """
        remote_addr = conn_info.get("remote_addr")
        if not remote_addr or remote_addr not in self.connection_start_times:
            return False
            
        # Calculate how long since connection was established
        start_time = self.connection_start_times[remote_addr]
        elapsed = time.time() - start_time
        
        # Very quick first data packet can indicate probing
        if "first_data_time" in conn_info:
            first_data_delay = conn_info["first_data_time"] - start_time
            if first_data_delay < 0.1:  # Less than 100ms delay is suspicious
                logger.debug(f"Suspicious timing: first data after {first_data_delay:.3f}s from {remote_addr}")
                return True
                
        # Multiple very short connections from same IP
        if remote_addr in self.probe_history:
            history = self.probe_history[remote_addr]
            if len(history) >= 3:  # 3 or more recent connections
                recent_conns = [t for t in history if time.time() - t < 60]  # Last minute
                if len(recent_conns) >= 3:
                    logger.debug(f"Suspicious connection pattern: {len(recent_conns)} connections in last minute from {remote_addr}")
                    return True
        
        # Check for probe stage progression (if we've seen multiple stages, it's suspicious)
        if remote_addr in self.ip_probe_stages:
            stages = self.ip_probe_stages[remote_addr]["stages_seen"]
            if len(stages) >= 2:
                logger.debug(f"Suspicious probe progression: IP {remote_addr} has tried {len(stages)} different probe stages")
                return True
        
        return False
    
    def _identify_probe_type(self, data: bytes) -> Optional[str]:
        """
        Identify the probe type based on the payload.
        
        Args:
            data: Packet payload
            
        Returns:
            Probe type identifier (e.g., "R1") or None if not identified
        """
        if not data:
            return None
            
        for probe_id, signature in self.probe_signatures.items():
            pattern = signature.get("pattern")
            if not pattern:
                continue
                
            if pattern in data:
                return probe_id
                
        return None
        
    def _check_staged_progression(self, remote_addr: str, probe_type: str) -> bool:
        """
        Check if the probe follows a logical stage progression.
        
        Args:
            remote_addr: Client IP address
            probe_type: Identified probe type
            
        Returns:
            True if the probe is part of a suspicious progression, False otherwise
        """
        if remote_addr not in self.ip_probe_stages or not probe_type:
            return False
            
        # Get stage information for this probe type
        probe_info = self.probe_signatures.get(probe_type, {})
        current_stage = probe_info.get("stage", 1)
        required_previous = probe_info.get("requires_previous", [])
        
        # Get history for this IP
        ip_history = self.ip_probe_stages[remote_addr]
        seen_stages = ip_history["stages_seen"]
        seen_probes = ip_history["probe_types_seen"]
        
        # Add this probe to history
        seen_stages.add(current_stage)
        seen_probes.add(probe_type)
        ip_history["last_probe_time"] = time.time()
        ip_history["total_probes"] += 1
        
        # Check required previous probes
        for req_probe in required_previous:
            if req_probe not in seen_probes:
                # This is suspicious - seeing an advanced probe without prerequisites
                logger.warning(f"Suspicious probe sequence: {probe_type} without required {req_probe} from {remote_addr}")
                return True
                
        # Check if we've seen multiple stages in sequence
        if len(seen_stages) > 1 and current_stage > 1:
            time_since_last = time.time() - ip_history["last_probe_time"]
            if time_since_last < 60:  # Within a minute of previous probes
                logger.debug(f"Staged probing detected from {remote_addr}: stages {sorted(seen_stages)}")
                return True
                
        return False
    
    def _check_payload_pattern(self, data: bytes, conn_info: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """
        Check if the payload matches known probe patterns.
        
        Args:
            data: Packet payload
            conn_info: Connection information
            
        Returns:
            Tuple of (is_probe, probe_type)
        """
        if not data:
            return False, None
            
        # Identify probe type
        probe_type = self._identify_probe_type(data)
        
        if probe_type:
            remote_addr = conn_info.get("remote_addr", "unknown")
            logger.debug(f"Detected {probe_type} probe from {remote_addr}")
            
            # Check for staged progression
            if self.staged_response and self._check_staged_progression(remote_addr, probe_type):
                return True, probe_type
                
            # Even if not part of a staged attack, still mark as a probe
            return True, probe_type
        
        # Check for other suspicious patterns
        remote_addr = conn_info.get("remote_addr", "unknown")
        packet_count = conn_info.get("packet_count", 0)
                
        # Unusual packet sizes (very small first packets)
        if len(data) < 10 and packet_count <= 1:
            logger.debug(f"Suspiciously small first packet ({len(data)} bytes) from {remote_addr}")
            return True, None
            
        # Random binary data in first packet when most protocols use text headers
        if packet_count <= 1:
            printable_count = sum(1 for b in data if 32 <= b <= 126)
            if len(data) > 10 and printable_count / len(data) < 0.3:
                logger.debug(f"Suspicious binary data in first packet: {printable_count}/{len(data)} printable from {remote_addr}")
                return True, None
                
        return False, None
    
    def is_probe_attempt(self, data: bytes, conn_info: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """
        Determine if a connection attempt matches GFW probe patterns.
        
        Args:
            data: The packet data to analyze
            conn_info: Connection information including metadata
            
        Returns:
            Tuple of (is_probe, probe_type)
        """
        remote_addr = conn_info.get("remote_addr")
        if not remote_addr:
            return False, None
            
        # Check for replay using the replay protection module
        if hasattr(self, 'replay_protection'):
            is_valid, _ = self.replay_protection.verify_packet(data, remote_addr, conn_info)
            if not is_valid:
                logger.warning(f"Replay attack detected from {remote_addr}")
                return True, "replay"
            
        # Update connection history for this IP
        if remote_addr not in self.probe_history:
            self.probe_history[remote_addr] = []
        self.probe_history[remote_addr].append(time.time())
        
        # Check for known probe patterns
        is_probe = False
        probe_type = None
        
        # Check TCP options
        if self._check_tcp_options(conn_info):
            logger.warning(f"Suspicious TCP options from {remote_addr}")
            is_probe = True
            
        # Check timing patterns
        if self._check_timing_pattern(conn_info):
            logger.warning(f"Suspicious timing pattern from {remote_addr}")
            is_probe = True
            
        # Check payload
        payload_is_probe, detected_type = self._check_payload_pattern(data, conn_info)
        if payload_is_probe:
            logger.warning(f"Suspicious payload pattern from {remote_addr} - type: {detected_type or 'unknown'}")
            is_probe = True
            probe_type = detected_type
            
        # If this is a probe, add to suspicious IPs and notify callbacks
        if is_probe:
            self.suspicious_ips.add(remote_addr)
            
            probe_info = {
                "timestamp": time.time(),
                "remote_addr": remote_addr,
                "data_len": len(data),
                "probe_type": probe_type,
                "connection_info": conn_info
            }
            
            # Notify callbacks
            for callback in self.alert_callbacks:
                try:
                    callback(remote_addr, probe_info)
                except Exception as e:
                    logger.error(f"Error in probe alert callback: {str(e)}")
                    
            # Periodically clean up old history (once per hour)
            current_time = time.time()
            if current_time - self.last_cleanup_time > 3600:
                self._cleanup_old_data()
                self.last_cleanup_time = current_time
                
        return is_probe, probe_type
    
    def handle_probe(self, data: bytes, conn_info: Dict[str, Any], 
                    probe_type: Optional[str] = None) -> Tuple[bool, Optional[bytes]]:
        """
        Handle a detected probe attempt based on configured strategy.
        
        Args:
            data: The packet data from the probe
            conn_info: Connection information
            probe_type: Type of probe detected, if known
            
        Returns:
            Tuple of (should_continue, response_data)
            - should_continue: Whether to continue processing this connection
            - response_data: Optional data to send back before closing connection
        """
        remote_addr = conn_info.get("remote_addr", "unknown")
        
        # Get the appropriate response strategy
        if probe_type and probe_type in self.probe_signatures:
            # Use probe-specific response strategy if defined
            response_strategy = self.probe_signatures[probe_type].get(
                "response", self.default_response_strategy
            )
        else:
            response_strategy = self.default_response_strategy
            
        logger.info(f"Handling {probe_type or 'unknown'} probe from {remote_addr} with strategy: {response_strategy}")
        
        # Apply consistent response timing if enabled
        if self.consistent_response_time:
            # Add a random delay within our configured range
            delay = random.uniform(self.minimum_response_delay, self.maximum_response_delay)
            time.sleep(delay)
        
        # Determine response based on strategy
        if response_strategy == "drop":
            # Option 1: Drop the connection
            return False, None
            
        elif response_strategy == "mislead":
            # Option 2: Send misleading response
            response = self._generate_misleading_response(data, conn_info, probe_type)
            return False, response
            
        elif response_strategy == "fingerprint":
            # Option 3: Fingerprint the probe for future detection
            self._update_probe_fingerprint(data, conn_info, probe_type)
            return False, None
            
        elif response_strategy == "none":
            # Option 4: No response (silent drop)
            return False, None
            
        elif response_strategy == "read_forever":
            # Option 5: Keep connection open but don't respond
            # This special strategy is useful against certain probes
            # The caller should keep the connection open but not send any data
            if self.read_forever_on_error:
                return True, None
            else:
                return False, None
                
        # Default: Drop silently
        return False, None
    
    def _generate_misleading_response(self, data: bytes, conn_info: Dict[str, Any], 
                                     probe_type: Optional[str] = None) -> bytes:
        """
        Generate a misleading response to confuse probes.
        
        Args:
            data: The packet data from the probe
            conn_info: Connection information
            probe_type: Type of probe detected, if known
            
        Returns:
            Response data to send back
        """
        # If we have a known probe type, use type-specific response
        if probe_type and probe_type in self.probe_signatures:
            probe_info = self.probe_signatures[probe_type]
            protocol = probe_info.get("protocol", "")
            if protocol and protocol in self.misleading_responses:
                return self.misleading_responses[protocol]()
        
        # Try to determine what protocol the probe is using
        protocol = "tls"  # Default
        
        # Look for protocol indicators in the data
        if data.startswith(b"\x16\x03"):  # TLS handshake
            protocol = "tls"
        elif b"HTTP/" in data or data.startswith(b"GET ") or data.startswith(b"POST "):
            protocol = "http"
        elif data.startswith(b"SSH-"):
            protocol = "ssh"
        elif len(data) >= 3 and data[0] == 0x05:  # SOCKS5
            protocol = "socks"
            
        # Get appropriate response generator
        response_generator = self.misleading_responses.get(protocol, self._generate_tls_error_response)
        
        # Generate and return response
        return response_generator()
    
    def _generate_tls_error_response(self) -> bytes:
        """Generate a TLS alert message as a misleading response."""
        # Randomize between different plausible TLS errors
        errors = [
            bytes.fromhex("1503030002020a"),  # TLS 1.2 handshake failure
            bytes.fromhex("1503030002021e"),  # TLS 1.2 bad record MAC
            bytes.fromhex("1503030002023c"),  # TLS 1.2 record overflow
            bytes.fromhex("1503030002014c"),  # TLS 1.2 internal error
        ]
        return random.choice(errors)
    
    def _generate_http_error_response(self) -> bytes:
        """Generate an HTTP error response."""
        # Return a variety of plausible HTTP errors
        responses = [
            b"HTTP/1.1 503 Service Unavailable\r\n"
            b"Content-Length: 0\r\n"
            b"Connection: close\r\n\r\n",
            
            b"HTTP/1.1 404 Not Found\r\n"
            b"Content-Length: 0\r\n"
            b"Connection: close\r\n\r\n",
            
            b"HTTP/1.1 400 Bad Request\r\n"
            b"Content-Length: 0\r\n"
            b"Connection: close\r\n\r\n",
        ]
        return random.choice(responses)
    
    def _generate_ssh_error_response(self) -> bytes:
        """Generate an SSH error response."""
        responses = [
            b"SSH-2.0-OpenSSH_7.4\r\n",
            b"SSH-2.0-OpenSSH_8.2\r\n",
            b"SSH-2.0-OpenSSH_7.6\r\n",
        ]
        return random.choice(responses)
    
    def _generate_socks_error_response(self) -> bytes:
        """Generate a SOCKS error response."""
        responses = [
            bytes([0x05, 0xFF]),  # SOCKS5 no acceptable methods
            bytes([0x05, 0x01, 0x01]),  # SOCKS5 general failure
        ]
        return random.choice(responses)
    
    def _update_probe_fingerprint(self, data: bytes, conn_info: Dict[str, Any], 
                                 probe_type: Optional[str] = None) -> None:
        """
        Update probe fingerprint database for future detection.
        
        Args:
            data: The packet data from the probe
            conn_info: Connection information
            probe_type: Type of probe detected, if known
        """
        remote_addr = conn_info.get("remote_addr", "unknown")
        
        # Create a fingerprint of the probe
        fingerprint = {
            "timestamp": time.time(),
            "remote_addr": remote_addr,
            "data_len": len(data),
            "data_prefix": data[:20].hex() if data else None,
            "tcp_options": conn_info.get("tcp_options"),
            "timing": {
                "connection_established": conn_info.get("connection_time"),
                "first_data": conn_info.get("first_data_time")
            },
            "probe_type": probe_type,
        }
        
        # In a real implementation, you'd store this in a database
        # For now, just log it
        logger.info(f"Fingerprinted probe: {json.dumps(fingerprint)}")
    
    def _cleanup_old_data(self) -> None:
        """Clean up old connection and probe history data."""
        # Remove old connection start times (older than 1 hour)
        current_time = time.time()
        cutoff_time = current_time - 3600
        
        # Clean connection times
        for addr in list(self.connection_start_times.keys()):
            if self.connection_start_times[addr] < cutoff_time:
                del self.connection_start_times[addr]
                
        # Clean probe history (keep last 24 hours)
        day_cutoff = current_time - 86400
        for addr in list(self.probe_history.keys()):
            self.probe_history[addr] = [t for t in self.probe_history[addr] if t > day_cutoff]
            if not self.probe_history[addr]:
                del self.probe_history[addr]
                
        # Clean probe stage history (keep last 24 hours)
        for addr in list(self.ip_probe_stages.keys()):
            last_probe = self.ip_probe_stages[addr].get("last_probe_time", 0)
            if last_probe < day_cutoff:
                del self.ip_probe_stages[addr] 