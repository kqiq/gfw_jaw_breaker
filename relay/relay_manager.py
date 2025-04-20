"""
Relay Manager module for coordinating the network of relay servers.
"""
import asyncio
import random
import time
import logging
import socket
import json
from typing import Dict, List, Any, Optional, Tuple, Set

from config.config import (
    RELAY_ENABLED,
    RELAY_NODES,
    MAX_RELAYS,
    LOG_LEVEL
)

# Configure logging
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class RelayNode:
    """Represents a single relay node in the network."""
    
    def __init__(self, host: str, port: int, region: str = "unknown", 
                load: float = 0.0, latency: float = 0.0):
        """
        Initialize a relay node.
        
        Args:
            host: Hostname or IP address of the relay
            port: Port number
            region: Geographic region of the relay
            load: Current load (0.0 to 1.0)
            latency: Latency in milliseconds
        """
        self.host = host
        self.port = port
        self.region = region
        self.load = load
        self.latency = latency
        self.last_ping = 0.0
        self.online = False
        self.capabilities = set()
        self.protocols = set()
        
    @property
    def address(self) -> str:
        """Get the address of the relay as 'host:port'."""
        return f"{self.host}:{self.port}"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert relay node to dictionary."""
        return {
            "host": self.host,
            "port": self.port,
            "region": self.region,
            "load": self.load,
            "latency": self.latency,
            "online": self.online,
            "capabilities": list(self.capabilities),
            "protocols": list(self.protocols),
            "last_ping": self.last_ping
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'RelayNode':
        """Create a relay node from dictionary."""
        node = cls(
            host=data["host"],
            port=data["port"],
            region=data.get("region", "unknown"),
            load=data.get("load", 0.0),
            latency=data.get("latency", 0.0)
        )
        node.online = data.get("online", False)
        node.capabilities = set(data.get("capabilities", []))
        node.protocols = set(data.get("protocols", []))
        node.last_ping = data.get("last_ping", 0.0)
        return node
    
    async def ping(self) -> Tuple[bool, float]:
        """
        Ping the relay node to check if it's online and measure latency.
        
        Returns:
            Tuple of (success, latency)
        """
        start_time = time.time()
        
        try:
            # Simple socket check
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect((self.host, self.port))
            s.close()
            
            latency = (time.time() - start_time) * 1000  # Convert to ms
            self.latency = latency
            self.online = True
            self.last_ping = time.time()
            
            return True, latency
            
        except Exception as e:
            logger.warning(f"Failed to ping relay {self.address}: {str(e)}")
            self.online = False
            self.last_ping = time.time()
            return False, 0.0

class RelayManager:
    """Manages a network of relay nodes for routing VPN traffic."""
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize the relay manager.
        
        Args:
            config: Configuration options
        """
        self.config = config or {}
        self.enabled = self.config.get('relay_enabled', RELAY_ENABLED)
        self.max_relays = self.config.get('max_relays', MAX_RELAYS)
        
        # Initialize relay nodes from config
        self.relays: Dict[str, RelayNode] = {}
        initial_relays = self.config.get('relay_nodes', RELAY_NODES)
        
        for relay_addr in initial_relays:
            try:
                if ':' in relay_addr:
                    host, port_str = relay_addr.split(':')
                    port = int(port_str)
                else:
                    host = relay_addr
                    port = 8443  # Default port
                
                relay = RelayNode(host, port)
                self.relays[relay.address] = relay
                
            except Exception as e:
                logger.error(f"Failed to parse relay address {relay_addr}: {str(e)}")
        
        self.ping_task = None
        self.running = False
        
        logger.info(f"Relay Manager initialized with {len(self.relays)} relays")
    
    async def start(self) -> None:
        """Start the relay manager and ping task."""
        if not self.enabled:
            logger.info("Relay Manager disabled, not starting")
            return
            
        if self.running:
            return
            
        self.running = True
        
        # Start periodic ping task
        self.ping_task = asyncio.create_task(self._ping_relays_task())
        
        logger.info("Relay Manager started")
    
    async def stop(self) -> None:
        """Stop the relay manager and ping task."""
        if not self.running:
            return
            
        self.running = False
        
        if self.ping_task:
            self.ping_task.cancel()
            try:
                await self.ping_task
            except asyncio.CancelledError:
                pass
            self.ping_task = None
            
        logger.info("Relay Manager stopped")
    
    async def _ping_relays_task(self) -> None:
        """Background task that periodically pings all relays to check status."""
        while self.running:
            try:
                await self.ping_all_relays()
                await asyncio.sleep(60)  # Ping every minute
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in ping relays task: {str(e)}")
                await asyncio.sleep(10)  # Wait a bit before retrying
    
    async def ping_all_relays(self) -> None:
        """Ping all relays to update their status."""
        ping_tasks = []
        
        for relay in self.relays.values():
            ping_tasks.append(relay.ping())
            
        # Wait for all pings to complete
        await asyncio.gather(*ping_tasks, return_exceptions=True)
        
        # Log status
        online_count = sum(1 for relay in self.relays.values() if relay.online)
        logger.info(f"Relay status: {online_count}/{len(self.relays)} online")
    
    def add_relay(self, host: str, port: int, region: str = "unknown") -> RelayNode:
        """
        Add a new relay to the network.
        
        Args:
            host: Hostname or IP of the relay
            port: Port number
            region: Geographic region
            
        Returns:
            The created RelayNode
        """
        relay = RelayNode(host, port, region)
        self.relays[relay.address] = relay
        logger.info(f"Added new relay: {relay.address} in region {region}")
        
        # Schedule ping to check status
        asyncio.create_task(relay.ping())
        
        return relay
    
    def remove_relay(self, address: str) -> bool:
        """
        Remove a relay from the network.
        
        Args:
            address: Relay address in format 'host:port'
            
        Returns:
            True if relay was removed, False otherwise
        """
        if address in self.relays:
            del self.relays[address]
            logger.info(f"Removed relay: {address}")
            return True
        return False
    
    def get_online_relays(self) -> List[RelayNode]:
        """Get a list of all online relays."""
        return [relay for relay in self.relays.values() if relay.online]
    
    def get_relays_by_region(self, region: str) -> List[RelayNode]:
        """Get all relays in a specific region."""
        return [relay for relay in self.relays.values() 
                if relay.region == region and relay.online]
    
    def select_relay_path(self, count: Optional[int] = None, 
                          preferred_regions: Optional[List[str]] = None) -> List[RelayNode]:
        """
        Select a path of relays for routing traffic.
        
        Args:
            count: Number of relays to select (default is max_relays)
            preferred_regions: List of preferred regions in order
            
        Returns:
            List of selected relay nodes
        """
        if not self.enabled:
            return []
            
        if count is None:
            count = self.max_relays
            
        # Get online relays
        online_relays = self.get_online_relays()
        
        if not online_relays:
            logger.warning("No online relays available")
            return []
            
        # Limit to requested count (or fewer if not enough relays)
        count = min(count, len(online_relays))
        
        if preferred_regions:
            # Try to select relays from preferred regions first
            selected_relays = []
            remaining_count = count
            
            for region in preferred_regions:
                if remaining_count <= 0:
                    break
                    
                region_relays = [r for r in online_relays 
                                if r.region == region and r not in selected_relays]
                
                # Take some relays from this region
                take_count = min(remaining_count, len(region_relays))
                if take_count > 0:
                    # Sort by load and latency (prefer low load, low latency)
                    sorted_relays = sorted(region_relays, 
                                          key=lambda r: (r.load, r.latency))
                    selected_relays.extend(sorted_relays[:take_count])
                    remaining_count -= take_count
            
            # If we still need more relays, take from any region
            if remaining_count > 0:
                remaining_relays = [r for r in online_relays if r not in selected_relays]
                sorted_relays = sorted(remaining_relays, 
                                      key=lambda r: (r.load, r.latency))
                selected_relays.extend(sorted_relays[:remaining_count])
                
            return selected_relays
        else:
            # Simple case: just sort by load and latency and take the best ones
            sorted_relays = sorted(online_relays, key=lambda r: (r.load, r.latency))
            return sorted_relays[:count]
    
    async def route_through_relays(self, data: bytes, relay_path: List[RelayNode]) -> bytes:
        """
        Route data through a path of relays.
        
        Note: This is a simplified implementation. A real implementation would
        establish connections to the relays and handle encryption between hops.
        
        Args:
            data: Data to route
            relay_path: List of relays to route through
            
        Returns:
            Response data
        """
        if not relay_path:
            logger.warning("No relay path provided, returning data as-is")
            return data
            
        # In a real implementation, this would establish connections through each relay
        # and route the data through them, handling encryption at each hop
        
        # For now, this is just a placeholder that simulates routing
        logger.info(f"Routing data through {len(relay_path)} relays: " + 
                   ", ".join(relay.address for relay in relay_path))
                   
        # Placeholder: return the original data
        return data 