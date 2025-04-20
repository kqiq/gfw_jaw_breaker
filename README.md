# Ultimate VPN Service

A high-performance, obfuscated VPN service designed to bypass the Great Firewall (GFW) and similar censorship systems with maximum speed and scalability.

## Features

- **Advanced Obfuscation**: Multiple protocol obfuscation techniques to evade deep packet inspection
- **Dynamic Protocol Switching**: Automatically changes protocols to avoid detection
- **Traffic Obfuscation**: Disguises VPN traffic as regular HTTPS traffic
- **Multipath Transmission**: Splits traffic across multiple paths for better reliability
- **Relay Network**: Scalable relay infrastructure for improved performance and censorship resistance
- **High-Speed Connections**: Optimized for maximum throughput
- **Extensible Architecture**: Easy to add new obfuscation methods and protocols
- **GFW-Specific Entropy Management**: Adjusts packet bit distribution to evade statistical analysis
- **First Packet ASCII Optimization**: Ensures first packets have optimal ASCII character ratios
- **Protocol Header Mimicry**: Makes connections look like legitimate HTTP or TLS traffic
- **Active Probe Detection**: Identifies and responds to GFW's active probing attempts
- **Dynamic Domain Fronting**: Rotates through trusted domains for enhanced circumvention

### New Enhanced Features

- **Hardware-Accelerated Cryptography**: Uses AES-NI, AVX2, and CUDA for blazing-fast encryption
- **Connection Pooling**: Reuses established tunnels for reduced latency and better performance
- **Adaptive Protocol Switching with ML**: Machine learning-based protocol selection based on success rates
- **Circuit Breaker Pattern**: Automatically fails over from problematic protocols
- **Real-time Performance Monitoring**: Tracks protocol success metrics across different regions
- **Advanced TCP Optimization**: Fine-tuned TCP parameters for optimal performance
- **Multi-path TCP Support**: Uses multiple network paths simultaneously for better throughput
- **Regional Protocol Optimization**: Learns optimal protocols for different regions
- **Decoy Traffic Generation**: Optional generation of benign-looking cover traffic
- **uvloop Integration**: High-performance event loop replacement for asyncio

## Components

1. **Enhanced VPN Engine**: Optimized core with connection pooling and hardware acceleration
2. **Obfuscation Layer**: Implements various obfuscation techniques
3. **Adaptive Protocol Switcher**: ML-based protocol switching to avoid detection
4. **Relay Manager**: Manages the network of relay servers
5. **Overlay Network**: Implements advanced firewall bypassing techniques
6. **Client Application**: User interface for connecting to the VPN
7. **GFW Evasion Manager**: Integrates specialized techniques for bypassing the Great Firewall
8. **Crypto Accelerator**: Hardware-accelerated cryptographic operations
9. **TCP Normalizer**: Adjusts TCP behavior to evade fingerprinting

## GFW Bypassing Techniques

This VPN service uses several advanced techniques to bypass internet censorship:

1. **Protocol Obfuscation**: Makes VPN traffic look like normal HTTPS, WebSocket, or HTTP traffic
2. **Domain Fronting**: Uses trusted CDNs to hide the actual destination of traffic
3. **Multi-path Routing**: Splits traffic across multiple paths to avoid detection
4. **Packet Fragmentation**: Breaks data into smaller chunks to evade deep packet inspection
5. **Adaptive Protocol Switching**: ML-based protocol selection based on real-time performance 
6. **Entropy Management**: Adjusts bit distribution of encrypted packets to avoid statistical analysis
7. **ASCII Optimization**: Ensures key packets contain sufficient printable ASCII characters
8. **Protocol Mimicry**: Adds realistic protocol headers to make traffic appear legitimate
9. **Active Probe Defense**: Detects and responds to active probing attempts
10. **Dynamic Domain Rotation**: Automatically switches between fronting domains based on performance
11. **Replay Protection**: Prevents replay attacks used by the GFW to identify proxy servers
12. **TCP Behavior Normalization**: Adjusts TCP parameters to look like legitimate browsers

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/ultimate-vpn-service.git
cd ultimate-vpn-service

# Install dependencies
pip install -r requirements.txt

# Optional: Install hardware acceleration dependencies
pip install torch cpuinfo
```

## Usage

### Running the Server

```bash
# Start the enhanced VPN server on default port (8443)
python server.py

# Custom host and port
python server.py --host 0.0.0.0 --port 8888

# Specify cryptographic acceleration method
python server.py --crypto-accel aes_ni

# Enable debug logging
python server.py --log-level DEBUG
```

### Running the Client

```bash
# Connect to a VPN server
python client.py --server vpn.example.com:8443

# Specify a protocol and obfuscation method
python client.py --server vpn.example.com:8443 --protocol shadowsocks --obfuscation tls

# Disable obfuscation
python client.py --server vpn.example.com:8443 --no-obfuscation

# Enable debug logging
python client.py --server vpn.example.com:8443 --log-level DEBUG
```

## Configuration

The VPN service can be configured through environment variables or by creating a `.env` file in the project directory. Here are some of the available configuration options:

```
# Server settings
SERVER_HOST=0.0.0.0
SERVER_PORT=8443

# Protocol settings
DEFAULT_PROTOCOL=shadowsocks
PROTOCOL_SWITCH_INTERVAL=3600

# Obfuscation settings
OBFUSCATION_ENABLED=True
DEFAULT_OBFUSCATION=tls

# Advanced settings
USE_MULTIPATH=False
PACKET_FRAGMENTATION=False
DOMAIN_FRONTING=False

# GFW Evasion settings
GFW_EVASION_ENABLED=True
GFW_FIRST_PACKET_OPTIMIZATION=True
GFW_BIT_DISTRIBUTION_ADJUSTMENTS=True
GFW_HEADER_MIMICRY=True
GFW_PROBE_DETECTION=True
GFW_PROBE_RESPONSE=mislead

# Enhanced Performance Settings
MAX_POOLED_CONNECTIONS=100
CONNECTION_TTL=300
IDLE_CONNECTION_TIMEOUT=60
PREFETCH_CONNECTIONS=true
PREFETCH_CONNECTION_COUNT=3

# Cryptographic Acceleration
PREFERRED_ACCELERATION=best  # best, aes_ni, avx2, avx512, openssl, cuda, none

# Adaptive Protocol Switching
ADAPTIVE_PROTOCOL_SWITCHING=true
PROTOCOL_SWITCHING_STRATEGY=adaptive  # adaptive, random, scheduled
MIN_PROTOCOL_SWITCH_INTERVAL=60
PROTOCOL_HISTORY_SIZE=100
PROTOCOL_CIRCUIT_BREAKER_THRESHOLD=3
PROTOCOL_CIRCUIT_BREAKER_RESET_TIME=300

# Multi-path TCP Settings
USE_MULTIPATH_TCP=false
MAX_PATHS=3
PATH_TIMEOUT=10.0

# Enhanced GFW Evasion
ADVANCED_TRAFFIC_MODELING=true
ENABLE_DECOY_TRAFFIC=false
DECOY_TRAFFIC_RATIO=0.1
```

## Adding Relay Nodes

To add relay nodes to the network, update the `RELAY_NODES` configuration:

```
# In .env file
RELAY_NODES=relay1.example.com:8443,relay2.example.com:8443
```

## Performance Optimization

The enhanced VPN service includes several performance optimizations:

1. **Hardware Acceleration**: Automatically detects and uses available hardware acceleration for cryptographic operations
2. **Connection Pooling**: Reuses existing connections to minimize connection establishment overhead
3. **uvloop**: Uses Cython-powered event loop implementation for improved async performance
4. **Prefetching**: Proactively establishes connections to commonly accessed destinations
5. **TCP Optimization**: Fine-tunes TCP parameters for optimal performance
6. **Adaptive Protocol Selection**: Uses ML to choose the fastest protocol for each region

## Security Considerations

- This software is designed for legitimate use cases such as accessing information in regions with internet restrictions
- Always comply with local laws and regulations when using this software
- The code includes secure encryption methods, but a full security audit is recommended before deploying in sensitive environments

## Extending the VPN

### Adding New Protocols

1. Create a new protocol implementation in the `protocols/` directory
2. Register the protocol in the `adaptive_protocol_switcher.py` file
3. Add the protocol to the `AVAILABLE_PROTOCOLS` list in the configuration

### Adding New Obfuscation Methods

1. Create a new obfuscation class in `protocols/obfuscation.py`
2. Add the method to the factory function
3. Add the method to the `AVAILABLE_OBFUSCATIONS` list in the configuration

### Adding New GFW Evasion Techniques

1. Implement the new technique in the appropriate module
2. Register the technique with the `GFWEvasionManager` in `core/gfw_evasion.py`
3. Add configuration options to `config.py`

### Adding New Acceleration Methods

1. Implement the new acceleration method in `utils/crypto_accelerator.py`
2. Add detection code to the `_detect_acceleration_methods` function
3. Add the method to the `AccelerationMethod` enum and selection logic

## License

MIT
