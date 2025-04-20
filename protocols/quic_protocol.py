"""
QUIC protocol implementation using aioquic.

Provides reliable, secure, multiplexed transport over UDP with improved performance
characteristics compared to TCP, including reduced connection establishment time,
improved congestion control, and connection migration support.
"""
import asyncio
import logging
import secrets
import time
import socket
import ssl
from typing import Dict, Any, Optional, Tuple, List, Set, Callable
from dataclasses import dataclass

from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import QuicEvent, StreamDataReceived
from aioquic.tls import SessionTicket, CipherSuite

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# List of secure cipher suites in preference order
CIPHER_SUITES = [
    CipherSuite.CHACHA20_POLY1305_SHA256,
    CipherSuite.AES_256_GCM_SHA384,
    CipherSuite.AES_128_GCM_SHA256,
]

@dataclass
class QUICConnectionInfo:
    """Information about a QUIC connection."""
    conn_id: str
    connection: QuicConnection
    protocol: QuicConnectionProtocol
    created_at: float
    last_active: float
    peer_address: Tuple[str, int]
    streams: Set[int]
    target_connections: Dict[int, Tuple[asyncio.StreamReader, asyncio.StreamWriter]]


class QUICServerProtocol(QuicConnectionProtocol):
    """QUIC protocol handler for the server side."""
    
    def __init__(self, *args, **kwargs):
        self.quic_protocol = kwargs.pop("quic_protocol", None)
        super().__init__(*args, **kwargs)
        self.streams = set()
        self.target_connections = {}
        
    def quic_event_received(self, event: QuicEvent) -> None:
        """Handle QUIC event."""
        if isinstance(event, StreamDataReceived):
            stream_id = event.stream_id
            self.streams.add(stream_id)
            
            if stream_id not in self.target_connections:
                # This is a new stream, parse the destination
                asyncio.create_task(self._handle_new_stream(stream_id, event.data))
            else:
                # Existing stream, forward the data
                asyncio.create_task(self._forward_to_target(stream_id, event.data))
                
    async def _handle_new_stream(self, stream_id: int, data: bytes) -> None:
        """Handle a new stream connection request."""
        try:
            # First byte is address type
            addr_type = data[0]
            
            if addr_type == 1:  # IPv4
                host = socket.inet_ntoa(data[1:5])
                port = int.from_bytes(data[5:7], byteorder='big')
                payload = data[7:]
            elif addr_type == 3:  # Domain
                domain_len = data[1]
                domain = data[2:2+domain_len].decode('utf-8')
                port = int.from_bytes(data[2+domain_len:4+domain_len], byteorder='big')
                host = domain
                payload = data[4+domain_len:]
            elif addr_type == 4:  # IPv6
                host = socket.inet_ntop(socket.AF_INET6, data[1:17])
                port = int.from_bytes(data[17:19], byteorder='big')
                payload = data[19:]
            else:
                logger.warning(f"Unknown address type: {addr_type}")
                self._quic.send_stream_data(stream_id, b'\x01\x00', end_stream=True)
                return
                
            logger.info(f"QUIC stream {stream_id} connecting to {host}:{port}")
            
            # Connect to the target
            try:
                target_reader, target_writer = await asyncio.open_connection(host, port)
                self.target_connections[stream_id] = (target_reader, target_writer)
                
                # Send any remaining data
                if payload:
                    target_writer.write(payload)
                    await target_writer.drain()
                    
                # Start forwarding from target to QUIC client
                asyncio.create_task(self._forward_from_target(stream_id, target_reader))
                
                # Signal success
                self._quic.send_stream_data(stream_id, b'\x00\x00')
                
            except Exception as e:
                logger.error(f"Failed to connect to target {host}:{port}: {e}")
                self._quic.send_stream_data(stream_id, b'\x01\x01', end_stream=True)
                
        except Exception as e:
            logger.error(f"Error handling new QUIC stream: {e}")
            self._quic.send_stream_data(stream_id, b'\x01\x02', end_stream=True)
    
    async def _forward_to_target(self, stream_id: int, data: bytes) -> None:
        """Forward data from QUIC client to target."""
        if stream_id in self.target_connections:
            try:
                _, target_writer = self.target_connections[stream_id]
                target_writer.write(data)
                await target_writer.drain()
            except Exception as e:
                logger.error(f"Error forwarding to target on stream {stream_id}: {e}")
                await self._close_stream(stream_id)
    
    async def _forward_from_target(self, stream_id: int, target_reader: asyncio.StreamReader) -> None:
        """Forward data from target to QUIC client."""
        try:
            while True:
                data = await target_reader.read(16384)
                if not data:
                    # End of stream
                    self._quic.send_stream_data(stream_id, b'', end_stream=True)
                    await self._close_stream(stream_id)
                    break
                    
                self._quic.send_stream_data(stream_id, data)
        except Exception as e:
            logger.error(f"Error forwarding from target on stream {stream_id}: {e}")
            await self._close_stream(stream_id)
    
    async def _close_stream(self, stream_id: int) -> None:
        """Close a stream and its associated resources."""
        if stream_id in self.target_connections:
            try:
                _, target_writer = self.target_connections[stream_id]
                target_writer.close()
                await target_writer.wait_closed()
            except Exception:
                pass
            finally:
                del self.target_connections[stream_id]
                
        if stream_id in self.streams:
            self.streams.remove(stream_id)


class QUICProtocol:
    """
    QUIC protocol implementation for the VPN service.
    
    This protocol provides faster connection establishment,
    multiplexed streams, and improved congestion control compared to TCP.
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize the QUIC protocol handler.
        
        Args:
            config: Configuration options
        """
        self.config = config or {}
        self.connections: Dict[str, QUICConnectionInfo] = {}
        
        # Configure QUIC
        self.quic_config = QuicConfiguration(
            alpn_protocols=["vpn-v1"],
            is_client=False,
            max_datagram_size=self.config.get("max_datagram_size", 1350),
            idle_timeout=self.config.get("idle_timeout", 60.0),
            cipher_suites=CIPHER_SUITES
        )
        
        # Load certificates
        cert_file = self.config.get("cert_file", "certs/server.crt")
        key_file = self.config.get("key_file", "certs/server.key")
        
        try:
            self.quic_config.load_cert_chain(cert_file, key_file)
        except Exception as e:
            logger.error(f"Failed to load certificates: {e}")
            logger.warning("QUIC will operate with a self-signed certificate")
            self._generate_self_signed_cert()
            
        # Session tickets for 0-RTT
        self.session_tickets: Dict[bytes, SessionTicket] = {}
            
    def _generate_self_signed_cert(self) -> None:
        """Generate a self-signed certificate."""
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
        import datetime
        
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        
        # Generate self-signed certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Ultimate VPN"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"vpn.example.com"),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"vpn.example.com")]),
            critical=False,
        ).sign(private_key, hashes.SHA256())
        
        # Save certificate and private key to memory
        cert_data = cert.public_bytes(Encoding.PEM)
        key_data = private_key.private_bytes(
            Encoding.PEM,
            PrivateFormat.PKCS8,
            NoEncryption()
        )
        
        # Load certificate directly from memory
        self.quic_config.certificate = cert_data
        self.quic_config.private_key = key_data
    
    async def start_server(self, host: str, port: int) -> None:
        """
        Start the QUIC server.
        
        Args:
            host: Hostname or IP to listen on
            port: Port number to listen on
        """
        logger.info(f"Starting QUIC server on {host}:{port}")
        
        await serve(
            host=host,
            port=port,
            configuration=self.quic_config,
            create_protocol=self._create_server_protocol,
            session_ticket_handler=self._handle_session_ticket,
            retry=self.config.get("use_retry", True)
        )
    
    def _create_server_protocol(self) -> QuicConnectionProtocol:
        """Create a new server protocol instance."""
        return QUICServerProtocol(
            quic=None,  # Will be set by serve()
            quic_protocol=self
        )
    
    def _handle_session_ticket(self, ticket: SessionTicket) -> None:
        """Store session tickets for 0-RTT."""
        ticket_key = secrets.token_bytes(16)
        self.session_tickets[ticket_key] = ticket
        logger.debug(f"New session ticket issued: {ticket_key.hex()}")
    
    async def handle_connection(self, reader: asyncio.StreamReader, 
                              writer: asyncio.StreamWriter) -> None:
        """
        Handle a client connection.
        
        This method is the entry point for the VPN engine to pass connections.
        For QUIC, we'll initialize through start_server() instead.
        
        Args:
            reader: StreamReader for reading client data
            writer: StreamWriter for writing data to client
        """
        peer = writer.get_extra_info('peername')
        logger.warning(f"Received connection from {peer} via handle_connection, "
                      "but QUIC should be initialized through start_server()")
        
        # Inform client that we need UDP for QUIC
        writer.write(b"QUIC requires UDP transport. Please reconnect using UDP.")
        await writer.drain()
        writer.close()
    
    async def stop(self) -> None:
        """Stop the QUIC server and clean up resources."""
        # Close all connections
        for conn_id, conn_info in list(self.connections.items()):
            try:
                conn_info.protocol.close()
            except Exception as e:
                logger.error(f"Error closing QUIC connection {conn_id}: {e}")
        
        self.connections.clear()
        self.session_tickets.clear()
        logger.info("QUIC server stopped") 