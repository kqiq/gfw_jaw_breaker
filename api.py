#!/usr/bin/env python3
"""
Ultimate VPN Service - API

A RESTful API for managing the VPN service.
"""
import asyncio
import argparse
import logging
import os
import signal
import sys
import uvicorn
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import psutil

# Add local modules to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config.config import (
    SERVER_HOST,
    SERVER_PORT,
    LOG_LEVEL,
    AVAILABLE_PROTOCOLS,
    AVAILABLE_OBFUSCATIONS,
    RELAY_NODES
)
from relay.relay_manager import RelayNode, RelayManager

# Configure logging
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("api")

# Initialize FastAPI app
app = FastAPI(
    title="Ultimate VPN Service API",
    description="API for managing the Ultimate VPN Service",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Pydantic models for API requests/responses
class ServerStatus(BaseModel):
    running: bool
    uptime: int
    connections: int
    cpu_usage: float
    memory_usage: float

class ConnectionInfo(BaseModel):
    id: str
    source: str
    destination: str
    protocol: str
    obfuscation: str
    connected_since: int
    bytes_sent: int
    bytes_received: int

class RelayNodeInfo(BaseModel):
    host: str
    port: int
    region: str = "unknown"
    load: float = 0.0
    latency: float = 0.0
    online: bool = False
    capabilities: List[str] = []
    protocols: List[str] = []
    last_ping: float = 0.0

class CreateRelayRequest(BaseModel):
    host: str
    port: int
    region: str = "unknown"

class Protocol(BaseModel):
    name: str
    enabled: bool

class Obfuscation(BaseModel):
    name: str
    enabled: bool

# Global variables
vpn_server_process = None
relay_manager = RelayManager()

# API endpoints
@app.get("/status", response_model=ServerStatus)
async def get_status():
    """Get the current status of the VPN server."""
    global vpn_server_process
    
    # Check if the server is running
    running = vpn_server_process is not None and vpn_server_process.is_running()
    
    # Get server statistics
    if running:
        try:
            process = psutil.Process(vpn_server_process.pid)
            uptime = int(time.time() - process.create_time())
            cpu_usage = process.cpu_percent()
            memory_usage = process.memory_percent()
            
            # For simplicity, just return a dummy connection count
            # In a real implementation, we would get this from the server
            connections = 0
        except Exception as e:
            logger.error(f"Error getting server status: {str(e)}")
            running = False
            uptime = 0
            cpu_usage = 0.0
            memory_usage = 0.0
            connections = 0
    else:
        uptime = 0
        cpu_usage = 0.0
        memory_usage = 0.0
        connections = 0
        
    return ServerStatus(
        running=running,
        uptime=uptime,
        connections=connections,
        cpu_usage=cpu_usage,
        memory_usage=memory_usage
    )

@app.post("/server/start")
async def start_server():
    """Start the VPN server."""
    global vpn_server_process
    
    # Check if server is already running
    if vpn_server_process is not None and vpn_server_process.is_running():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Server is already running"
        )
    
    try:
        # Start the server as a subprocess
        server_path = os.path.join(os.path.dirname(__file__), "server.py")
        vpn_server_process = await asyncio.create_subprocess_exec(
            sys.executable, server_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        # Wait a bit to see if the server starts successfully
        await asyncio.sleep(1)
        
        if vpn_server_process.returncode is not None:
            # Server failed to start
            stdout, stderr = await vpn_server_process.communicate()
            vpn_server_process = None
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to start server: {stderr.decode()}"
            )
            
        # Start the relay manager
        await relay_manager.start()
        
        return {"status": "success", "message": "Server started successfully"}
        
    except Exception as e:
        logger.error(f"Error starting server: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error starting server: {str(e)}"
        )

@app.post("/server/stop")
async def stop_server():
    """Stop the VPN server."""
    global vpn_server_process
    
    # Check if server is running
    if vpn_server_process is None or not vpn_server_process.is_running():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Server is not running"
        )
    
    try:
        # Stop the relay manager
        await relay_manager.stop()
        
        # Send SIGTERM to the server process
        vpn_server_process.terminate()
        
        # Wait for the process to exit
        await vpn_server_process.wait()
        vpn_server_process = None
        
        return {"status": "success", "message": "Server stopped successfully"}
        
    except Exception as e:
        logger.error(f"Error stopping server: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error stopping server: {str(e)}"
        )

@app.get("/protocols", response_model=List[Protocol])
async def get_protocols():
    """Get the list of available protocols."""
    # In a real implementation, we would query the server for enabled protocols
    # For simplicity, we just return all protocols as enabled
    protocols = [
        Protocol(name=proto, enabled=True)
        for proto in AVAILABLE_PROTOCOLS
    ]
    return protocols

@app.get("/obfuscations", response_model=List[Obfuscation])
async def get_obfuscations():
    """Get the list of available obfuscation methods."""
    # In a real implementation, we would query the server for enabled obfuscation methods
    # For simplicity, we just return all methods as enabled
    obfuscations = [
        Obfuscation(name=obfs, enabled=True)
        for obfs in AVAILABLE_OBFUSCATIONS
    ]
    return obfuscations

@app.get("/relays", response_model=List[RelayNodeInfo])
async def get_relays():
    """Get the list of relay nodes."""
    relays = relay_manager.get_online_relays()
    
    relay_infos = []
    for relay in relays:
        relay_infos.append(RelayNodeInfo(
            host=relay.host,
            port=relay.port,
            region=relay.region,
            load=relay.load,
            latency=relay.latency,
            online=relay.online,
            capabilities=list(relay.capabilities),
            protocols=list(relay.protocols),
            last_ping=relay.last_ping
        ))
    
    return relay_infos

@app.post("/relays", response_model=RelayNodeInfo)
async def add_relay(relay_data: CreateRelayRequest):
    """Add a new relay node."""
    relay = relay_manager.add_relay(
        relay_data.host,
        relay_data.port,
        relay_data.region
    )
    
    # Ping the relay to check if it's online
    await relay.ping()
    
    return RelayNodeInfo(
        host=relay.host,
        port=relay.port,
        region=relay.region,
        load=relay.load,
        latency=relay.latency,
        online=relay.online,
        capabilities=list(relay.capabilities),
        protocols=list(relay.protocols),
        last_ping=relay.last_ping
    )

@app.delete("/relays/{relay_id}")
async def remove_relay(relay_id: str):
    """Remove a relay node."""
    success = relay_manager.remove_relay(relay_id)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Relay {relay_id} not found"
        )
    
    return {"status": "success", "message": f"Relay {relay_id} removed successfully"}

@app.post("/relays/ping")
async def ping_relays():
    """Ping all relay nodes to update their status."""
    await relay_manager.ping_all_relays()
    return {"status": "success", "message": "All relays pinged successfully"}

async def main():
    """Main function to start the API server."""
    parser = argparse.ArgumentParser(description='Ultimate VPN Service API')
    parser.add_argument('--host', type=str, default='0.0.0.0',
                        help='Host to bind the API server to')
    parser.add_argument('--port', type=int, default=8080,
                        help='Port to bind the API server to')
    parser.add_argument('--log-level', type=str, default=LOG_LEVEL,
                        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        help='Logging level')
    
    args = parser.parse_args()
    
    # Configure logging level from args
    logging.getLogger().setLevel(getattr(logging, args.log_level))
    
    # Set up signal handlers for graceful shutdown
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda: sys.exit(0))
    
    # Start Uvicorn server
    config = uvicorn.Config(
        app=app,
        host=args.host,
        port=args.port,
        log_level=args.log_level.lower()
    )
    server = uvicorn.Server(config)
    await server.serve()

if __name__ == "__main__":
    # Need to import here to avoid circular imports
    import time
    asyncio.run(main()) 