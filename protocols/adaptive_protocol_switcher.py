"""
Adaptive Protocol Switcher with machine learning capabilities.

This module intelligently switches between protocols based on connection quality,
GFW detection patterns, and historical success rates.
"""
import asyncio
import random
import time
import logging
import json
import os
from typing import Dict, List, Any, Callable, Optional, Tuple, Set
from datetime import datetime
from collections import deque

from protocols.quic_protocol import QUICProtocol

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ProtocolPerformanceTracker:
    """
    Tracks and analyzes protocol performance over time.
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize the performance tracker.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        
        # How many recent events to keep per protocol
        self.history_size = self.config.get('protocol_history_size', 100)
        
        # History of success/failure events by protocol
        self.protocol_history: Dict[str, List[Dict[str, Any]]] = {}
        
        # Recent connection quality measurements by protocol
        self.connection_quality: Dict[str, deque] = {}
        
        # Success rates cache
        self.success_rates: Dict[str, float] = {}
        self.success_rates_updated = 0
        
        # Performance by region/country
        self.regional_performance: Dict[str, Dict[str, Dict[str, float]]] = {}
        
        # Load history from disk if available
        self._load_history()
        
    def record_connection_attempt(self, protocol: str, success: bool, 
                                duration: float, region: str = None,
                                error_type: str = None, metadata: Dict[str, Any] = None) -> None:
        """
        Record a connection attempt result.
        
        Args:
            protocol: Protocol name
            success: Whether the connection succeeded
            duration: Connection duration in seconds
            region: Region/country code
            error_type: Type of error if failed
            metadata: Additional metadata about the connection
        """
        # Initialize protocol history if needed
        if protocol not in self.protocol_history:
            self.protocol_history[protocol] = []
            
        # Initialize connection quality tracking if needed
        if protocol not in self.connection_quality:
            self.connection_quality[protocol] = deque(maxlen=self.history_size)
        
        # Create the event record
        event = {
            'timestamp': time.time(),
            'success': success,
            'duration': duration,
            'region': region,
            'error_type': error_type
        }
        
        # Add metadata if provided
        if metadata:
            event['metadata'] = metadata
            
        # Add to protocol history
        self.protocol_history[protocol].append(event)
        
        # Trim history if needed
        while len(self.protocol_history[protocol]) > self.history_size:
            self.protocol_history[protocol].pop(0)
            
        # Record connection quality (for successful connections)
        if success and duration > 0:
            # Higher is better (1/duration)
            quality = min(1.0, 5.0 / max(0.1, duration))  # Cap at 1.0
            self.connection_quality[protocol].append(quality)
            
        # Update regional performance
        if region:
            if region not in self.regional_performance:
                self.regional_performance[region] = {}
                
            if protocol not in self.regional_performance[region]:
                self.regional_performance[region][protocol] = {
                    'attempts': 0,
                    'successes': 0,
                    'avg_duration': 0,
                    'success_rate': 0
                }
                
            # Update regional stats
            stats = self.regional_performance[region][protocol]
            stats['attempts'] += 1
            if success:
                stats['successes'] += 1
                
            if success and duration > 0:
                # Update running average of duration
                stats['avg_duration'] = (stats['avg_duration'] * (stats['successes'] - 1) + duration) / stats['successes']
                
            # Update success rate
            stats['success_rate'] = stats['successes'] / stats['attempts']
        
        # Invalidate success rate cache
        self.success_rates = {}
        
        # Save history periodically
        if random.random() < 0.1:  # 10% chance to save on each update
            self._save_history()
    
    def get_success_rate(self, protocol: str, window_seconds: int = 3600) -> float:
        """
        Get the success rate for a protocol over the specified time window.
        
        Args:
            protocol: Protocol name
            window_seconds: Time window in seconds
            
        Returns:
            Success rate as a float between 0 and 1
        """
        # Check if we have data for this protocol
        if protocol not in self.protocol_history or not self.protocol_history[protocol]:
            return 0.0
            
        # Use cached value if available and recent
        cache_key = f"{protocol}_{window_seconds}"
        if self.success_rates and time.time() - self.success_rates_updated < 60:  # Cache for 60 seconds
            return self.success_rates.get(cache_key, 0.0)
            
        # Calculate success rate
        current_time = time.time()
        cutoff_time = current_time - window_seconds
        
        # Filter events within time window
        recent_events = [
            event for event in self.protocol_history[protocol]
            if event['timestamp'] >= cutoff_time
        ]
        
        if not recent_events:
            return 0.0
            
        # Count successes
        successes = sum(1 for event in recent_events if event['success'])
        success_rate = successes / len(recent_events)
        
        # Cache the result
        self.success_rates[cache_key] = success_rate
        self.success_rates_updated = current_time
        
        return success_rate
    
    def get_connection_quality(self, protocol: str) -> float:
        """
        Get the average connection quality for a protocol.
        
        Args:
            protocol: Protocol name
            
        Returns:
            Average connection quality (higher is better)
        """
        if protocol not in self.connection_quality or not self.connection_quality[protocol]:
            return 0.0
            
        return sum(self.connection_quality[protocol]) / len(self.connection_quality[protocol])
    
    def get_best_protocol_for_region(self, region: str, 
                                    available_protocols: List[str] = None) -> Optional[str]:
        """
        Get the best protocol for a specific region based on historical performance.
        
        Args:
            region: Region/country code
            available_protocols: List of available protocols to consider
            
        Returns:
            Best protocol name or None if no data
        """
        if region not in self.regional_performance:
            return None
            
        regional_data = self.regional_performance[region]
        
        # Filter by available protocols if specified
        protocols = available_protocols or list(regional_data.keys())
        protocols = [p for p in protocols if p in regional_data]
        
        if not protocols:
            return None
            
        # Sort by success rate, then by average duration (lower is better)
        best_protocol = max(
            protocols,
            key=lambda p: (
                regional_data[p]['success_rate'],
                -regional_data[p]['avg_duration']
            )
        )
        
        return best_protocol
    
    def _load_history(self) -> None:
        """Load protocol history from disk."""
        history_file = self.config.get('history_file', 'protocol_history.json')
        
        try:
            if os.path.exists(history_file):
                with open(history_file, 'r') as f:
                    data = json.load(f)
                    
                    self.protocol_history = data.get('protocol_history', {})
                    self.regional_performance = data.get('regional_performance', {})
                    
                    # Rebuild connection quality from history
                    for protocol, events in self.protocol_history.items():
                        self.connection_quality[protocol] = deque(maxlen=self.history_size)
                        
                        for event in events:
                            if event.get('success') and event.get('duration', 0) > 0:
                                quality = min(1.0, 5.0 / max(0.1, event['duration']))
                                self.connection_quality[protocol].append(quality)
                                
                logger.info(f"Loaded protocol history for {len(self.protocol_history)} protocols")
        except Exception as e:
            logger.error(f"Error loading protocol history: {str(e)}")
    
    def _save_history(self) -> None:
        """Save protocol history to disk."""
        history_file = self.config.get('history_file', 'protocol_history.json')
        
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(os.path.abspath(history_file)), exist_ok=True)
            
            # Prepare data for saving
            data = {
                'protocol_history': self.protocol_history,
                'regional_performance': self.regional_performance,
                'last_updated': time.time()
            }
            
            # Save to temporary file first
            temp_file = f"{history_file}.tmp"
            with open(temp_file, 'w') as f:
                json.dump(data, f)
                
            # Rename to final file
            os.replace(temp_file, history_file)
            
            logger.debug(f"Saved protocol history to {history_file}")
        except Exception as e:
            logger.error(f"Error saving protocol history: {str(e)}")


class AdaptiveProtocolSwitcher:
    """
    Adaptively switches between available protocols based on connection quality and GFW evasion success.
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize the protocol switcher.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        
        # Available protocols
        self.available_protocols = ['trojan', 'vmess', 'shadowsocks', 'quic']
        
        # Default protocol
        self.default_protocol = self.config.get('default_protocol', 'trojan')
        self.current_protocol = self.default_protocol
        
        # Protocol handlers (initialized on demand)
        self.protocol_handlers: Dict[str, Any] = {}
        
        # Performance tracker
        self.performance_tracker = ProtocolPerformanceTracker(self.config)
        
        # Switching preferences
        self.auto_switch = self.config.get('auto_switch', True)
        self.switch_threshold = self.config.get('protocol_switch_threshold', 0.7)
        self.circuit_breaker_threshold = self.config.get('circuit_breaker_threshold', 0.3)
        self.circuit_breaker_reset_time = self.config.get('circuit_breaker_reset_time', 300)
        self.min_time_between_switches = self.config.get('min_time_between_switches', 60)
        self.session_rotation_enabled = self.config.get('session_rotation_enabled', True)
        self.rotation_probability = self.config.get('rotation_probability', 0.1)  # 10% chance per check
        
        # Circuit breaker state
        self.broken_circuits: Dict[str, float] = {}
        
        # GFW detection counter and thresholds
        self.gfw_detection_count = 0
        self.gfw_detection_threshold = self.config.get('gfw_detection_threshold', 3)
        self.gfw_detection_window = self.config.get('gfw_detection_window', 600)
        self.gfw_detection_times: List[float] = []
        
        # Switch callback
        self.switch_callbacks: List[Callable[[str, str], None]] = []
        
        # State
        self.running = False
        self.switch_task = None
        self.last_switch_time = 0
        self.last_gfw_detection = 0  # Initialize the missing attribute
        
        logger.info(f"Adaptive Protocol Switcher initialized with default protocol: {self.default_protocol}")
        
    def register_protocol(self, name: str, handler: Callable) -> None:
        """
        Register a protocol handler.
        
        Args:
            name: Protocol name
            handler: Protocol handler
        """
        self.protocol_handlers[name] = handler
        logger.info(f"Registered protocol handler: {name}")
        
        # Add to available protocols if not already there
        if name not in self.available_protocols:
            self.available_protocols.append(name)
    
    def register_switch_callback(self, callback: Callable[[str, str], None]) -> None:
        """
        Register a callback for protocol switches.
        
        Args:
            callback: Callback function taking old_protocol and new_protocol
        """
        self.switch_callbacks.append(callback)
    
    def get_current_protocol(self) -> str:
        """Get the current protocol name."""
        return self.current_protocol
    
    def get_current_handler(self) -> Optional[Callable]:
        """Get the current protocol handler."""
        self._ensure_handler_loaded(self.current_protocol)
        return self.protocol_handlers.get(self.current_protocol)
    
    async def start(self) -> None:
        """Start the protocol switcher."""
        if self.running:
            return
        self.running = True
        self.switch_task = asyncio.create_task(self._switch_task())
        
    async def stop(self) -> None:
        """Stop the protocol switcher."""
        if not self.running:
            return
        self.running = False
        
        if self.switch_task:
            self.switch_task.cancel()
            try:
                await self.switch_task
            except asyncio.CancelledError:
                pass
        
        logger.info("Protocol switcher stopped")
    
    async def switch_protocol(self, new_protocol: Optional[str] = None,
                            reason: str = 'manual') -> bool:
        """
        Switch to a different protocol.
        
        Args:
            new_protocol: Protocol to switch to (None for automatic selection)
            reason: Reason for switching
            
        Returns:
            Success flag
        """
        # Don't switch if we've switched recently (unless it's manual)
        current_time = time.time()
        if (reason != 'manual' and 
            current_time - self.last_switch_time < self.min_time_between_switches):
            logger.debug(f"Not switching protocol: too soon since last switch "
                        f"({current_time - self.last_switch_time:.1f}s)")
            return False
        
        old_protocol = self.current_protocol
        
        # Determine the new protocol
        if new_protocol is None:
            # Use automatic selection
            available_protocols = [p for p in self.available_protocols 
                                 if p != old_protocol and p not in self.broken_circuits]
            
            if not available_protocols:
                logger.warning("No available protocols to switch to")
                
                # Reset a circuit breaker if all are broken
                if len(self.broken_circuits) >= len(self.available_protocols) - 1:
                    oldest_broken = min(self.broken_circuits.items(), key=lambda x: x[1])
                    del self.broken_circuits[oldest_broken[0]]
                    logger.info(f"Reset circuit breaker for {oldest_broken[0]} as all protocols were broken")
                    
                    # Try again with the reset circuit
                    available_protocols = [p for p in self.available_protocols 
                                        if p != old_protocol and p not in self.broken_circuits]
                    
                    if not available_protocols:
                        logger.error("Still no available protocols after circuit breaker reset")
                        return False
            
            # Select the best protocol
            new_protocol = self._select_best_protocol(available_protocols, reason)
            
        elif new_protocol not in self.available_protocols:
            logger.error(f"Requested protocol {new_protocol} is not available")
            return False
            
        # Check if the protocol is the same (no need to switch)
        if new_protocol == old_protocol:
            logger.debug(f"Not switching protocol: already using {old_protocol}")
            return True
            
        # Ensure the handler is loaded
        self._ensure_handler_loaded(new_protocol)
        if new_protocol not in self.protocol_handlers:
            logger.error(f"Failed to load handler for protocol {new_protocol}")
            return False
            
        # Switch to the new protocol
        self.current_protocol = new_protocol
        self.last_switch_time = current_time
        
        logger.info(f"Switched protocol: {old_protocol} -> {new_protocol} (reason: {reason})")
        
        # Notify callbacks
        for callback in self.switch_callbacks:
            try:
                callback(old_protocol, new_protocol)
            except Exception as e:
                logger.error(f"Error in protocol switch callback: {str(e)}")
                
        return True
        
    def _ensure_handler_loaded(self, protocol: str) -> None:
        """Ensure a protocol handler is loaded."""
        if protocol in self.protocol_handlers:
            return
            
        # Load the handler based on protocol name
        try:
            if protocol == 'trojan':
                from protocols.trojan_protocol import TrojanProtocol
                self.protocol_handlers[protocol] = TrojanProtocol(self.config)
                
            elif protocol == 'vmess':
                from protocols.vmess_protocol import VMessProtocol
                self.protocol_handlers[protocol] = VMessProtocol(self.config)
                
            elif protocol == 'shadowsocks':
                from protocols.shadowsocks_protocol import ShadowsocksProtocol
                self.protocol_handlers[protocol] = ShadowsocksProtocol(self.config)
                
            elif protocol == 'quic':
                from protocols.quic_protocol import QUICProtocol
                self.protocol_handlers[protocol] = QUICProtocol(self.config)
                
            else:
                logger.error(f"Unknown protocol: {protocol}")
                
        except Exception as e:
            logger.error(f"Error loading protocol handler for {protocol}: {str(e)}")

    def _select_best_protocol(self, available_protocols: List[str], reason: str) -> str:
        """
        Select the best protocol based on performance data.
        
        Args:
            available_protocols: List of available protocols to choose from
            reason: Reason for protocol selection
            
        Returns:
            Best protocol based on available data
        """
        if not available_protocols:
            return self.current_protocol
            
        # If only one protocol, use it
        if len(available_protocols) == 1:
            return available_protocols[0]
            
        # If no current protocol, pick randomly
        if not self.current_protocol:
            return random.choice(available_protocols)
            
        # Weight factors based on reason
        weights = dict(self.feature_weights)
        if reason == 'gfw_detection':
            # Prioritize success rate when GFW detection happens
            weights['success_rate'] = 0.7
            weights['connection_quality'] = 0.2
            weights['regional_performance'] = 0.1
            
        # Score each protocol
        scores = {}
        for protocol in available_protocols:
            # Start with a base score
            score = 0.0
            
            # Add weighted success rate
            success_rate = self.performance_tracker.get_success_rate(protocol, 3600)
            score += success_rate * weights['success_rate']
            
            # Add weighted connection quality
            quality = self.performance_tracker.get_connection_quality(protocol)
            score += quality * weights['connection_quality']
            
            # Add weighted regional performance if region is known
            region = self.config.get('current_region')
            if region and weights['regional_performance'] > 0:
                best_regional = self.performance_tracker.get_best_protocol_for_region(region, available_protocols)
                if best_regional == protocol:
                    score += weights['regional_performance']
                    
            # Store score
            scores[protocol] = score
            
        # Add randomness to prevent complete predictability
        randomness = self.config.get('selection_randomness', 0.1)
        for protocol in scores:
            scores[protocol] += random.uniform(0, randomness)
            
        # Select protocol with highest score
        best_protocol = max(scores.items(), key=lambda x: x[1])[0]
        
        # Don't switch to same protocol
        if best_protocol == self.current_protocol and len(available_protocols) > 1:
            # Choose second best
            del scores[best_protocol]
            best_protocol = max(scores.items(), key=lambda x: x[1])[0]
            
        return best_protocol
        
    def _is_circuit_broken(self, protocol: str) -> bool:
        """
        Check if the circuit breaker is tripped for a protocol.
        
        Args:
            protocol: Protocol to check
            
        Returns:
            True if circuit breaker is tripped, False otherwise
        """
        if protocol not in self.circuit_breakers:
            return False
            
        breaker = self.circuit_breakers[protocol]
        
        if not breaker['tripped']:
            return False
            
        # Check if circuit breaker should be reset
        if time.time() - breaker['trip_time'] > self.circuit_breaker_reset_time:
            # Reset the circuit breaker
            breaker['tripped'] = False
            breaker['failures'] = 0
            logger.info(f"Circuit breaker reset for protocol {protocol}")
            return False
            
        return True
        
    async def _switch_task(self) -> None:
        """Background task that periodically evaluates and switches protocols."""
        while self.running:
            try:
                # Sleep with jitter to avoid detection
                jitter = random.uniform(-10, 10)
                await asyncio.sleep(60 + jitter)  # Check roughly every minute
                
                # Determine if we should switch
                should_switch = False
                reason = None
                
                # Check for recent GFW detection
                if time.time() - self.last_gfw_detection < self.gfw_detection_threshold:
                    should_switch = True
                    reason = 'gfw_detection'
                    
                # Check if current protocol performance is poor
                elif self.current_protocol:
                    success_rate = self.performance_tracker.get_success_rate(self.current_protocol, 600)  # Last 10 minutes
                    if success_rate < 0.5:  # If success rate drops below 50%
                        should_switch = True
                        reason = 'poor_performance'
                        
                # Random rotation for session unpredictability
                elif self.session_rotation_enabled and random.random() < self.rotation_probability:
                    should_switch = True
                    reason = 'rotation'
                    
                if should_switch:
                    await self.switch_protocol(reason=reason or 'periodic')
                    
            except asyncio.CancelledError:
                logger.info("Protocol switch task cancelled")
                break
            except Exception as e:
                logger.error(f"Error in protocol switch task: {str(e)}")
                await asyncio.sleep(5)  # Wait a bit before retrying 