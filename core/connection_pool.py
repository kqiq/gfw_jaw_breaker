"""
Connection Pool for optimizing VPN connections.

This module implements an efficient connection pool that reuses established
tunnels to reduce connection overhead and improve performance.
"""
import asyncio
import logging
import time
import random
from typing import Dict, List, Tuple, Optional, Set, Any, Union
from dataclasses import dataclass
from enum import Enum
import uuid

from aioquic.quic.connection import QuicConnection

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ConnectionState(Enum):
    """Connection state enum."""
    IDLE = 0
    IN_USE = 1
    CLOSING = 2


@dataclass
class PooledConnection:
    """Represents a connection in the pool."""
    id: str
    reader: Optional[asyncio.StreamReader]
    writer: Optional[asyncio.StreamWriter]
    quic_connection: Optional[QuicConnection]
    created_at: float
    last_used_at: float
    state: ConnectionState
    destination: Tuple[str, int]
    protocol: str
    stats: Dict[str, Any]


class ConnectionPool:
    """
    Manages a pool of reusable connections to improve performance.
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize the connection pool.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        
        # Pool settings
        self.max_connections = self.config.get('max_pooled_connections', 100)
        self.connection_ttl = self.config.get('connection_ttl', 300)  # 5 minutes
        self.idle_timeout = self.config.get('idle_timeout', 60)  # 1 minute
        self.prefetch_enabled = self.config.get('prefetch_connections', True)
        self.prefetch_count = self.config.get('prefetch_connection_count', 3)
        
        # Connection storage by destination
        self.connections: Dict[Tuple[str, int], List[PooledConnection]] = {}
        
        # Connection storage by ID for fast lookup
        self.connection_by_id: Dict[str, PooledConnection] = {}
        
        # QUIC connections by destination
        self.quic_connections: Dict[Tuple[str, int], List[PooledConnection]] = {}
        
        # Connection migration mappings
        # Maps client_id to a list of connection IDs that can be migrated between
        self.migration_groups: Dict[str, Set[str]] = {}
        
        # Common destinations for prefetching
        self.common_destinations: Dict[Tuple[str, int], int] = {}
        
        # Tracking stats
        self.stats = {
            'created': 0,
            'reused': 0,
            'expired': 0,
            'errors': 0,
            'active': 0,
            'migrations': 0,
            'quic_connections': 0
        }
        
        # Background tasks
        self.cleanup_task = None
        self.prefetch_task = None
        self.running = False
        
        logger.info("Connection pool initialized")
    
    async def start(self):
        """Start the connection pool background tasks."""
        if self.running:
            return
            
        self.running = True
        self.cleanup_task = asyncio.create_task(self._cleanup_task())
        
        if self.prefetch_enabled:
            self.prefetch_task = asyncio.create_task(self._prefetch_task())
            
        logger.info("Connection pool started")
    
    async def stop(self):
        """Stop the connection pool and close all connections."""
        if not self.running:
            return
            
        self.running = False
        
        # Cancel background tasks
        if self.cleanup_task:
            self.cleanup_task.cancel()
            try:
                await self.cleanup_task
            except asyncio.CancelledError:
                pass
                
        if self.prefetch_task:
            self.prefetch_task.cancel()
            try:
                await self.prefetch_task
            except asyncio.CancelledError:
                pass
                
        # Close all connections
        all_connections = list(self.connection_by_id.values())
        for conn in all_connections:
            await self._close_connection(conn)
            
        self.connections.clear()
        self.connection_by_id.clear()
        self.quic_connections.clear()
        self.migration_groups.clear()
        
        logger.info("Connection pool stopped")
    
    async def get_connection(self, destination: Tuple[str, int], protocol: str = 'default',
                           create_func = None) -> Tuple[Optional[asyncio.StreamReader], 
                                                      Optional[asyncio.StreamWriter], 
                                                      bool]:
        """
        Get a connection from the pool or create a new one.
        
        Args:
            destination: (host, port) tuple
            protocol: Protocol name
            create_func: Function to create new connection if needed
            
        Returns:
            Tuple of (reader, writer, is_new)
        """
        # Update common destinations stats
        self.common_destinations[destination] = self.common_destinations.get(destination, 0) + 1
        
        # Check if we have an idle connection for this destination
        if destination in self.connections:
            idle_connections = [
                conn for conn in self.connections[destination] 
                if conn.state == ConnectionState.IDLE and conn.protocol == protocol
            ]
            
            # Check each idle connection
            for conn in idle_connections:
                # Check if the connection is still alive
                if conn.writer and conn.writer.is_closing():
                    # Connection is closed, remove it
                    await self._close_connection(conn)
                    continue
                    
                # Check if connection is expired
                if time.time() - conn.created_at > self.connection_ttl:
                    # Connection too old, close it
                    await self._close_connection(conn)
                    continue
                
                # Reuse this connection
                conn.state = ConnectionState.IN_USE
                conn.last_used_at = time.time()
                self.stats['reused'] += 1
                self.stats['active'] += 1
                
                logger.debug(f"Reusing connection to {destination}")
                return conn.reader, conn.writer, False
        
        # No suitable connection found, create a new one
        if create_func:
            try:
                reader, writer = await create_func(destination[0], destination[1])
                
                # Register the new connection
                conn_id = str(uuid.uuid4())
                connection = PooledConnection(
                    id=conn_id,
                    reader=reader,
                    writer=writer,
                    quic_connection=None,
                    created_at=time.time(),
                    last_used_at=time.time(),
                    state=ConnectionState.IN_USE,
                    destination=destination,
                    protocol=protocol,
                    stats={'bytes_sent': 0, 'bytes_received': 0}
                )
                
                # Add to storage
                if destination not in self.connections:
                    self.connections[destination] = []
                self.connections[destination].append(connection)
                self.connection_by_id[conn_id] = connection
                
                self.stats['created'] += 1
                self.stats['active'] += 1
                
                logger.debug(f"Created new connection to {destination}")
                return reader, writer, True
                
            except Exception as e:
                logger.error(f"Error creating connection to {destination}: {str(e)}")
                self.stats['errors'] += 1
                return None, None, False
        else:
            logger.error(f"No create_func provided for {destination}")
            return None, None, False
    
    async def get_quic_connection(self, destination: Tuple[str, int], 
                                create_func = None) -> Tuple[Optional[QuicConnection], bool]:
        """
        Get a QUIC connection from the pool or create a new one.
        
        Args:
            destination: (host, port) tuple
            create_func: Function to create new QUIC connection if needed
            
        Returns:
            Tuple of (QuicConnection, is_new)
        """
        # Update common destinations stats
        self.common_destinations[destination] = self.common_destinations.get(destination, 0) + 1
        
        # Check if we have an idle QUIC connection for this destination
        if destination in self.quic_connections:
            idle_connections = [
                conn for conn in self.quic_connections[destination] 
                if conn.state == ConnectionState.IDLE
            ]
            
            # Check each idle connection
            for conn in idle_connections:
                # Check if the connection is still valid
                quic_conn = conn.quic_connection
                if quic_conn and not quic_conn.is_closing:
                    # Reuse this connection
                    conn.state = ConnectionState.IN_USE
                    conn.last_used_at = time.time()
                    self.stats['reused'] += 1
                    self.stats['active'] += 1
                    
                    logger.debug(f"Reusing QUIC connection to {destination}")
                    return quic_conn, False
                else:
                    # Connection is closed, remove it
                    await self._close_connection(conn)
                    continue
        
        # No suitable connection found, create a new one
        if create_func:
            try:
                quic_conn = await create_func(destination[0], destination[1])
                
                # Register the new connection
                conn_id = str(uuid.uuid4())
                connection = PooledConnection(
                    id=conn_id,
                    reader=None,
                    writer=None,
                    quic_connection=quic_conn,
                    created_at=time.time(),
                    last_used_at=time.time(),
                    state=ConnectionState.IN_USE,
                    destination=destination,
                    protocol='quic',
                    stats={'bytes_sent': 0, 'bytes_received': 0, 'streams': 0}
                )
                
                # Add to storage
                if destination not in self.quic_connections:
                    self.quic_connections[destination] = []
                self.quic_connections[destination].append(connection)
                self.connection_by_id[conn_id] = connection
                
                self.stats['created'] += 1
                self.stats['active'] += 1
                self.stats['quic_connections'] += 1
                
                logger.debug(f"Created new QUIC connection to {destination}")
                return quic_conn, True
                
            except Exception as e:
                logger.error(f"Error creating QUIC connection to {destination}: {str(e)}")
                self.stats['errors'] += 1
                return None, False
        else:
            logger.error(f"No create_func provided for QUIC connection to {destination}")
            return None, False
    
    async def release_connection(self, reader: Optional[asyncio.StreamReader] = None, 
                               writer: Optional[asyncio.StreamWriter] = None,
                               quic_connection: Optional[QuicConnection] = None,
                               keep_alive: bool = True) -> None:
        """
        Release a connection back to the pool.
        
        Args:
            reader: StreamReader object
            writer: StreamWriter object
            quic_connection: QuicConnection object
            keep_alive: Whether to keep the connection alive in the pool
        """
        if not reader and not writer and not quic_connection:
            logger.error("Must provide either reader/writer pair or QuicConnection")
            return
            
        # Find the connection
        conn = None
        if reader and writer:
            # Find by reader/writer
            for conn_id, connection in self.connection_by_id.items():
                if connection.reader == reader and connection.writer == writer:
                    conn = connection
                    break
        elif quic_connection:
            # Find by QuicConnection
            for conn_id, connection in self.connection_by_id.items():
                if connection.quic_connection == quic_connection:
                    conn = connection
                    break
                    
        if not conn:
            logger.warning("Connection not found in pool, nothing to release")
            return
            
        # Update state
        if keep_alive and not (writer and writer.is_closing()):
            conn.state = ConnectionState.IDLE
            conn.last_used_at = time.time()
            self.stats['active'] -= 1
            logger.debug(f"Released connection {conn.id} to {conn.destination} back to pool")
        else:
            # Close the connection
            await self._close_connection(conn)
            logger.debug(f"Closed connection {conn.id} to {conn.destination}")
    
    def register_for_migration(self, client_id: str, connection_id: str) -> None:
        """
        Register a connection for migration.
        
        Args:
            client_id: Client identifier
            connection_id: Connection identifier
        """
        if client_id not in self.migration_groups:
            self.migration_groups[client_id] = set()
        self.migration_groups[client_id].add(connection_id)
        
    async def migrate_connection(self, old_connection_id: str, 
                               new_connection_id: str) -> bool:
        """
        Migrate a connection from old to new.
        
        Args:
            old_connection_id: Old connection ID
            new_connection_id: New connection ID
            
        Returns:
            Success flag
        """
        if old_connection_id not in self.connection_by_id:
            logger.error(f"Old connection {old_connection_id} not found for migration")
            return False
            
        if new_connection_id not in self.connection_by_id:
            logger.error(f"New connection {new_connection_id} not found for migration")
            return False
            
        # Check if both connections belong to the same migration group
        for client_id, conn_ids in self.migration_groups.items():
            if old_connection_id in conn_ids and new_connection_id in conn_ids:
                old_conn = self.connection_by_id[old_connection_id]
                new_conn = self.connection_by_id[new_connection_id]
                
                # Copy state from old to new
                new_conn.stats = old_conn.stats.copy()
                
                # Update stats
                self.stats['migrations'] += 1
                
                logger.info(f"Migrated connection {old_connection_id} to {new_connection_id}")
                return True
                
        logger.error(f"Connections {old_connection_id} and {new_connection_id} not in same migration group")
        return False
    
    def _is_pool_full(self) -> bool:
        """Check if the pool is full."""
        return len(self.connection_by_id) >= self.max_connections
    
    async def _cleanup_task(self) -> None:
        """Background task that cleans up expired connections."""
        try:
            while self.running:
                # Sleep first to avoid immediate cleanup on startup
                await asyncio.sleep(30)  # Check every 30 seconds
                
                if not self.running:
                    break
                    
                current_time = time.time()
                to_close = []
                
                # Find expired connections
                for conn_id, conn in list(self.connection_by_id.items()):
                    # Close idle connections that have been idle too long
                    if (conn.state == ConnectionState.IDLE and 
                        current_time - conn.last_used_at > self.idle_timeout):
                        to_close.append(conn)
                        
                    # Close any connection that's too old
                    elif current_time - conn.created_at > self.connection_ttl:
                        to_close.append(conn)
                
                # Close the expired connections
                for conn in to_close:
                    await self._close_connection(conn)
                    self.stats['expired'] += 1
                    
                # Also clean up migration groups
                for client_id in list(self.migration_groups.keys()):
                    # Remove connection IDs that no longer exist
                    self.migration_groups[client_id] = {
                        conn_id for conn_id in self.migration_groups[client_id]
                        if conn_id in self.connection_by_id
                    }
                    
                    # Remove empty groups
                    if not self.migration_groups[client_id]:
                        del self.migration_groups[client_id]
                
                # Log stats periodically
                if random.random() < 0.2:  # ~20% chance each cleanup
                    logger.info(f"Connection pool stats: {self.get_stats()}")
                    
        except asyncio.CancelledError:
            logger.debug("Cleanup task cancelled")
        except Exception as e:
            logger.error(f"Error in connection pool cleanup task: {str(e)}")
    
    async def _prefetch_task(self) -> None:
        """Background task that prefetches connections to common destinations."""
        try:
            while self.running:
                # Sleep first to allow some history to accumulate
                await asyncio.sleep(60)  # Check every minute
                
                if not self.running or self._is_pool_full():
                    continue
                    
                # Find top N most common destinations
                top_destinations = sorted(
                    self.common_destinations.items(),
                    key=lambda x: x[1],
                    reverse=True
                )[:self.prefetch_count]
                
                # Prefetch connections
                for destination, count in top_destinations:
                    # Skip if we already have connections to this destination
                    if (destination in self.connections and 
                        any(c.state == ConnectionState.IDLE for c in self.connections[destination])):
                        continue
                        
                    # Skip if we already have QUIC connections to this destination
                    if (destination in self.quic_connections and 
                        any(c.state == ConnectionState.IDLE for c in self.quic_connections[destination])):
                        continue
                        
                    # Create a background task to prefetch
                    asyncio.create_task(self._prefetch_connection(destination))
                    
        except asyncio.CancelledError:
            logger.debug("Prefetch task cancelled")
        except Exception as e:
            logger.error(f"Error in connection pool prefetch task: {str(e)}")
    
    async def _prefetch_connection(self, destination: Tuple[str, int]) -> None:
        """
        Prefetch a connection to a destination.
        
        Args:
            destination: (host, port) tuple
        """
        logger.debug(f"Prefetching connection to {destination}")
        try:
            # This would normally use a proper connection factory
            reader, writer = await asyncio.open_connection(destination[0], destination[1])
            
            # Register in the pool
            conn_id = str(uuid.uuid4())
            connection = PooledConnection(
                id=conn_id,
                reader=reader,
                writer=writer,
                quic_connection=None,
                created_at=time.time(),
                last_used_at=time.time(),
                state=ConnectionState.IDLE,  # Start as idle
                destination=destination,
                protocol='default',
                stats={'bytes_sent': 0, 'bytes_received': 0, 'prefetched': True}
            )
            
            # Add to storage
            if destination not in self.connections:
                self.connections[destination] = []
            self.connections[destination].append(connection)
            self.connection_by_id[conn_id] = connection
            
            self.stats['created'] += 1
            
            logger.debug(f"Prefetched connection to {destination}")
            
        except Exception as e:
            logger.warning(f"Failed to prefetch connection to {destination}: {str(e)}")
    
    async def _close_connection(self, conn: PooledConnection) -> None:
        """
        Close a connection and remove it from the pool.
        
        Args:
            conn: PooledConnection object
        """
        # Mark as closing to prevent reuse during closing
        conn.state = ConnectionState.CLOSING
        
        try:
            # Close TCP connection if present
            if conn.writer:
                conn.writer.close()
                try:
                    await conn.writer.wait_closed()
                except Exception:
                    pass
                    
            # Close QUIC connection if present
            if conn.quic_connection:
                conn.quic_connection.close()
                
            # Update stats if active
            if conn.state == ConnectionState.IN_USE:
                self.stats['active'] -= 1
                
            # Remove from storage
            if conn.destination in self.connections:
                self.connections[conn.destination] = [
                    c for c in self.connections[conn.destination] if c.id != conn.id
                ]
                if not self.connections[conn.destination]:
                    del self.connections[conn.destination]
                    
            if conn.destination in self.quic_connections:
                self.quic_connections[conn.destination] = [
                    c for c in self.quic_connections[conn.destination] if c.id != conn.id
                ]
                if not self.quic_connections[conn.destination]:
                    del self.quic_connections[conn.destination]
                    
            if conn.id in self.connection_by_id:
                del self.connection_by_id[conn.id]
                
            # Remove from migration groups
            for client_id, conn_ids in self.migration_groups.items():
                if conn.id in conn_ids:
                    conn_ids.remove(conn.id)
            
        except Exception as e:
            logger.error(f"Error closing connection {conn.id}: {str(e)}")
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get statistics about the connection pool.
        
        Returns:
            Dictionary of statistics
        """
        return {
            'total_connections': len(self.connection_by_id),
            'active_connections': self.stats['active'],
            'idle_connections': len(self.connection_by_id) - self.stats['active'],
            'total_created': self.stats['created'],
            'total_reused': self.stats['reused'],
            'total_expired': self.stats['expired'],
            'total_errors': self.stats['errors'],
            'total_migrations': self.stats['migrations'],
            'quic_connections': self.stats['quic_connections'],
            'unique_destinations': len(self.connections) + len(self.quic_connections),
            'migration_groups': len(self.migration_groups)
        } 