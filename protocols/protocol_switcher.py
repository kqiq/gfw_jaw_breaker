"""
Protocol Switcher module for dynamically switching between VPN protocols.
"""
import asyncio
import random
import time
import logging
from typing import Dict, Any, List, Callable, Optional

from config.config import (
    DEFAULT_PROTOCOL,
    AVAILABLE_PROTOCOLS,
    PROTOCOL_SWITCH_INTERVAL,
    LOG_LEVEL
)

# Configure logging
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ProtocolSwitcher:
    """
    Dynamically switches between different VPN protocols to avoid detection.
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize the protocol switcher.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.current_protocol = self.config.get('default_protocol', DEFAULT_PROTOCOL)
        self.available_protocols = self.config.get('available_protocols', AVAILABLE_PROTOCOLS)
        self.switch_interval = self.config.get('protocol_switch_interval', PROTOCOL_SWITCH_INTERVAL)
        self.last_switch_time = time.time()
        self.protocol_handlers = {}
        self.switch_callbacks = []
        self.running = False
        self.switch_task = None
        
        # Ensure current protocol is in available protocols
        if self.current_protocol not in self.available_protocols:
            self.current_protocol = self.available_protocols[0] if self.available_protocols else None
            
        logger.info(f"Protocol Switcher initialized with protocol: {self.current_protocol}")
    
    def register_protocol(self, name: str, handler: Callable) -> None:
        """
        Register a protocol handler.
        
        Args:
            name: Protocol name
            handler: Protocol handler function/class
        """
        self.protocol_handlers[name] = handler
        logger.info(f"Registered protocol handler for: {name}")
        
        # If this is our first protocol and we don't have a current protocol set
        if not self.current_protocol and name in self.available_protocols:
            self.current_protocol = name
    
    def register_switch_callback(self, callback: Callable[[str, str], None]) -> None:
        """
        Register a callback to be notified when protocols are switched.
        
        Args:
            callback: Function to call when switching protocols
                     Takes (old_protocol, new_protocol) as arguments
        """
        self.switch_callbacks.append(callback)
    
    def get_current_protocol(self) -> str:
        """Get the name of the currently active protocol."""
        return self.current_protocol
    
    def get_current_handler(self) -> Optional[Callable]:
        """Get the handler for the currently active protocol."""
        if self.current_protocol in self.protocol_handlers:
            return self.protocol_handlers[self.current_protocol]
        return None
    
    async def switch_protocol(self, new_protocol: Optional[str] = None) -> bool:
        """
        Switch to a different protocol.
        
        Args:
            new_protocol: Protocol to switch to. If None, a random protocol is chosen.
            
        Returns:
            True if switch was successful, False otherwise
        """
        if not self.available_protocols:
            logger.warning("No available protocols to switch to")
            return False
            
        # If no specific protocol requested, choose a random one
        if not new_protocol:
            # Don't switch to the same protocol we're already using
            available = [p for p in self.available_protocols if p != self.current_protocol]
            if not available:
                logger.info("Only one protocol available, no switch needed")
                return False
                
            new_protocol = random.choice(available)
        
        # Check if requested protocol is available
        if new_protocol not in self.available_protocols:
            logger.warning(f"Requested protocol {new_protocol} not in available protocols")
            return False
            
        # Check if we have a handler for the protocol
        if new_protocol not in self.protocol_handlers:
            logger.warning(f"No handler registered for protocol {new_protocol}")
            return False
            
        old_protocol = self.current_protocol
        self.current_protocol = new_protocol
        self.last_switch_time = time.time()
        
        logger.info(f"Switched protocol from {old_protocol} to {new_protocol}")
        
        # Notify callbacks
        for callback in self.switch_callbacks:
            try:
                callback(old_protocol, new_protocol)
            except Exception as e:
                logger.error(f"Error in protocol switch callback: {str(e)}")
        
        return True
    
    async def _switch_task(self) -> None:
        """Background task that periodically switches protocols."""
        while self.running:
            try:
                # Sleep until next switch time
                current_time = time.time()
                time_since_last_switch = current_time - self.last_switch_time
                
                if time_since_last_switch >= self.switch_interval:
                    await self.switch_protocol()
                    wait_time = self.switch_interval
                else:
                    wait_time = self.switch_interval - time_since_last_switch
                
                # Add some randomness to avoid pattern detection
                jitter = random.uniform(-wait_time * 0.1, wait_time * 0.1)
                wait_time += jitter
                
                # Ensure wait time is positive
                wait_time = max(1, wait_time)
                
                await asyncio.sleep(wait_time)
                
            except asyncio.CancelledError:
                logger.info("Protocol switch task cancelled")
                break
            except Exception as e:
                logger.error(f"Error in protocol switch task: {str(e)}")
                await asyncio.sleep(5)  # Wait a bit before retrying
    
    async def start(self) -> None:
        """Start the automatic protocol switching."""
        if self.running:
            return
            
        self.running = True
        self.switch_task = asyncio.create_task(self._switch_task())
        logger.info("Started automatic protocol switching")
    
    async def stop(self) -> None:
        """Stop the automatic protocol switching."""
        if not self.running:
            return
            
        self.running = False
        if self.switch_task:
            self.switch_task.cancel()
            try:
                await self.switch_task
            except asyncio.CancelledError:
                pass
            self.switch_task = None
            
        logger.info("Stopped automatic protocol switching") 