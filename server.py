#!/usr/bin/env python3
"""
Ultimate VPN Service Server

This script starts the VPN service with all its components.
"""
import asyncio
import logging
import argparse
import os
import sys
import signal
from typing import Dict, Any

from core.enhanced_vpn_engine import EnhancedVPNEngine
from config.config import get_config, DEFAULT_PORT, DEFAULT_QUIC_PORT, LOG_LEVEL

# Configure logging
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("server")

# Global variables
vpn_engine = None
shutdown_event = None

async def start_server(config: Dict[str, Any]) -> None:
    """
    Start the VPN server.
    
    Args:
        config: Configuration dictionary
    """
    global vpn_engine, shutdown_event
    
    # Create shutdown event
    shutdown_event = asyncio.Event()
    
    # Create VPN engine
    vpn_engine = EnhancedVPNEngine(config)
    
    # Get host and port
    host = config.get('host', '0.0.0.0')
    port = config.get('port', DEFAULT_PORT)
    quic_port = config.get('quic_port', DEFAULT_QUIC_PORT)
    
    # Start the server
    logger.info(f"Starting VPN server on {host}:{port} (QUIC port: {quic_port})")
    
    try:
        await vpn_engine.start_server(host, port, quic_port)
    except Exception as e:
        logger.error(f"Error starting server: {str(e)}")
        shutdown_event.set()

async def shutdown() -> None:
    """Shutdown the server gracefully."""
    global vpn_engine, shutdown_event
    
    if vpn_engine:
        logger.info("Shutting down VPN server...")
        await vpn_engine.stop_server()
        
    if shutdown_event:
        shutdown_event.set()

def signal_handler():
    """Handle termination signals."""
    asyncio.create_task(shutdown())

async def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(description='Ultimate VPN Service Server')
    parser.add_argument('-c', '--config', help='Path to config file')
    parser.add_argument('-p', '--port', type=int, help='Port to listen on')
    parser.add_argument('--quic-port', type=int, help='Port for QUIC protocol')
    parser.add_argument('-H', '--host', help='Host to bind to')
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug logging')
    
    args = parser.parse_args()
    
    # Load config
    config = get_config()
    
    # Override with command line arguments
    if args.config:
        config['CONFIG_FILE'] = args.config
        
    if args.port:
        config['port'] = args.port
        
    if args.quic_port:
        config['quic_port'] = args.quic_port
        
    if args.host:
        config['host'] = args.host
        
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        config['LOG_LEVEL'] = 'DEBUG'
    
    # Setup signal handlers
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop = asyncio.get_running_loop()
        loop.add_signal_handler(sig, signal_handler)
    
    # Start the server
    await start_server(config)
    
    # Wait for shutdown
    await shutdown_event.wait()
    
    logger.info("Server stopped")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Interrupted by user")
    except Exception as e:
        logger.error(f"Unhandled exception: {str(e)}", exc_info=True)
        sys.exit(1) 