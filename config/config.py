"""
Configuration settings for the Ultimate VPN Service.
"""
import os
from dotenv import load_dotenv
import json
import logging
from typing import Dict, Any, Optional

# Load environment variables from .env file if it exists
load_dotenv()

# Server settings
SERVER_HOST = os.getenv("SERVER_HOST", "0.0.0.0")
SERVER_PORT = int(os.getenv("SERVER_PORT", "8443"))
DEFAULT_PORT = SERVER_PORT  # Alias for backward compatibility

# Client settings
CLIENT_TIMEOUT = int(os.getenv("CLIENT_TIMEOUT", "30"))

# Protocol settings
DEFAULT_PROTOCOL = os.getenv("DEFAULT_PROTOCOL", "shadowsocks")
AVAILABLE_PROTOCOLS = ["shadowsocks", "openvpn", "wireguard", "trojan", "vmess"]
PROTOCOL_SWITCH_INTERVAL = int(os.getenv("PROTOCOL_SWITCH_INTERVAL", "3600"))  # in seconds
ENABLE_ADAPTIVE_PROTOCOL = os.getenv("ENABLE_ADAPTIVE_PROTOCOL", "True").lower() == "true"
ENABLE_QUIC = os.getenv("ENABLE_QUIC", "True").lower() == "true"

# Obfuscation settings
OBFUSCATION_ENABLED = os.getenv("OBFUSCATION_ENABLED", "True").lower() == "true"
DEFAULT_OBFUSCATION = os.getenv("DEFAULT_OBFUSCATION", "tls")
AVAILABLE_OBFUSCATIONS = ["tls", "http", "websocket", "random_padding"]

# Relay network settings
RELAY_ENABLED = os.getenv("RELAY_ENABLED", "True").lower() == "true"
RELAY_NODES = os.getenv("RELAY_NODES", "").split(",") if os.getenv("RELAY_NODES") else []
MAX_RELAYS = int(os.getenv("MAX_RELAYS", "3"))

# Encryption settings
ENCRYPTION_METHOD = os.getenv("ENCRYPTION_METHOD", "aes-256-gcm")

# Performance settings
CONCURRENT_CONNECTIONS = int(os.getenv("CONCURRENT_CONNECTIONS", "100"))
BUFFER_SIZE = int(os.getenv("BUFFER_SIZE", "8192"))
USE_CONNECTION_POOL = os.getenv("USE_CONNECTION_POOL", "True").lower() == "true"

# Logging settings
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_FILE = os.getenv("LOG_FILE", "vpn_service.log")

# Advanced settings
USE_MULTIPATH = os.getenv("USE_MULTIPATH", "False").lower() == "true"
PACKET_FRAGMENTATION = os.getenv("PACKET_FRAGMENTATION", "False").lower() == "true"
DOMAIN_FRONTING = os.getenv("DOMAIN_FRONTING", "False").lower() == "true"

# GFW Evasion settings
GFW_EVASION_ENABLED = os.getenv("GFW_EVASION_ENABLED", "True").lower() == "true"
GFW_FIRST_PACKET_OPTIMIZATION = os.getenv("GFW_FIRST_PACKET_OPTIMIZATION", "True").lower() == "true"
GFW_BIT_DISTRIBUTION_ADJUSTMENTS = os.getenv("GFW_BIT_DISTRIBUTION_ADJUSTMENTS", "True").lower() == "true"
GFW_HEADER_MIMICRY = os.getenv("GFW_HEADER_MIMICRY", "True").lower() == "true"
GFW_PROBE_DETECTION = os.getenv("GFW_PROBE_DETECTION", "True").lower() == "true"
GFW_PROBE_RESPONSE = os.getenv("GFW_PROBE_RESPONSE", "mislead")  # Options: "drop", "mislead", "fingerprint", "none", "read_forever"
GFW_ALWAYS_ADJUST_FIRST_PACKET = os.getenv("GFW_ALWAYS_ADJUST_FIRST_PACKET", "True").lower() == "true"
GFW_DEFAULT_HEADER_MIMICRY = os.getenv("GFW_DEFAULT_HEADER_MIMICRY", "tls")  # Options: "http", "tls", "random"

# Packet Fragmentation and Size Settings
ENABLE_PACKET_FRAGMENTATION = os.getenv("ENABLE_PACKET_FRAGMENTATION", "True").lower() == "true"
FRAGMENTATION_PROBABILITY = float(os.getenv("FRAGMENTATION_PROBABILITY", "0.7"))
MAX_FRAGMENTS = int(os.getenv("MAX_FRAGMENTS", "3"))
ENABLE_VARIABLE_PADDING = os.getenv("ENABLE_VARIABLE_PADDING", "True").lower() == "true"
RANDOMIZE_PACKET_SIZES = os.getenv("RANDOMIZE_PACKET_SIZES", "True").lower() == "true"

# Domain Fronting settings
DOMAIN_FRONTING_ENABLED = os.getenv("DOMAIN_FRONTING_ENABLED", "True").lower() == "true"
TRUSTED_DOMAINS = os.getenv("TRUSTED_DOMAINS", "cloudfront.net,akamaized.net,cloudflare.com").split(",") if os.getenv("TRUSTED_DOMAINS") else []
DOMAIN_CHECK_INTERVAL = int(os.getenv("DOMAIN_CHECK_INTERVAL", "3600"))  # in seconds
DOMAIN_TEST_URL = os.getenv("DOMAIN_TEST_URL", "https://www.google.com")
FALLBACK_DOMAINS = os.getenv("FALLBACK_DOMAINS", "cloudfront.net,azureedge.net").split(",") if os.getenv("FALLBACK_DOMAINS") else []

# Replay Protection Settings
REPLAY_PROTECTION_ENABLED = os.getenv("REPLAY_PROTECTION_ENABLED", "True").lower() == "true"
NONCE_EXPIRATION_SECONDS = int(os.getenv("NONCE_EXPIRATION_SECONDS", "3600"))  # 1 hour
MAX_NONCES = int(os.getenv("MAX_NONCES", "10000"))
CONNECTION_WINDOW_SECONDS = int(os.getenv("CONNECTION_WINDOW_SECONDS", "5"))
CONNECTION_HISTORY_SIZE = int(os.getenv("CONNECTION_HISTORY_SIZE", "1000"))
REPLAY_DETECTION_WINDOW_SECONDS = int(os.getenv("REPLAY_DETECTION_WINDOW_SECONDS", "30"))
SUSPICIOUS_REPEAT_THRESHOLD = int(os.getenv("SUSPICIOUS_REPEAT_THRESHOLD", "3"))

# TCP Normalization Settings
NORMALIZE_TCP_BEHAVIOR = os.getenv("NORMALIZE_TCP_BEHAVIOR", "True").lower() == "true"
NORMALIZE_WINDOW_SIZE = os.getenv("NORMALIZE_WINDOW_SIZE", "True").lower() == "true"
RANDOM_WINDOW_SIZE = os.getenv("RANDOM_WINDOW_SIZE", "True").lower() == "true"
DEFAULT_WINDOW_SIZE = int(os.getenv("DEFAULT_WINDOW_SIZE", "65535"))
NORMALIZE_TTL = os.getenv("NORMALIZE_TTL", "True").lower() == "true"
TTL_OS = os.getenv("TTL_OS", "windows")  # OS profile to mimic: windows, linux, macos
NORMALIZE_RESPONSE_TIMING = os.getenv("NORMALIZE_RESPONSE_TIMING", "True").lower() == "true"
MIN_RESPONSE_DELAY = float(os.getenv("MIN_RESPONSE_DELAY", "0.05"))
MAX_RESPONSE_DELAY = float(os.getenv("MAX_RESPONSE_DELAY", "0.2"))
READ_FOREVER_ON_ERROR = os.getenv("READ_FOREVER_ON_ERROR", "False").lower() == "true"

# Adaptive Defense Settings
ADAPTIVE_DEFENSE_MODE = os.getenv("ADAPTIVE_DEFENSE_MODE", "True").lower() == "true"
CIRCUIT_BREAKER_WINDOW_SECONDS = int(os.getenv("CIRCUIT_BREAKER_WINDOW_SECONDS", "60"))
CIRCUIT_BREAKER_THRESHOLD = int(os.getenv("CIRCUIT_BREAKER_THRESHOLD", "5"))
DEFAULT_DEFENSE_LEVEL = os.getenv("DEFAULT_DEFENSE_LEVEL", "normal")  # Options: normal, enhanced, paranoid

# Connection Pool Settings
MAX_POOLED_CONNECTIONS = int(os.getenv("MAX_POOLED_CONNECTIONS", "100"))
CONNECTION_TTL = int(os.getenv("CONNECTION_TTL", "300"))  # 5 minutes
IDLE_CONNECTION_TIMEOUT = int(os.getenv("IDLE_CONNECTION_TIMEOUT", "60"))  # 1 minute
PREFETCH_CONNECTIONS = os.getenv("PREFETCH_CONNECTIONS", "True").lower() == "true"
PREFETCH_CONNECTION_COUNT = int(os.getenv("PREFETCH_CONNECTION_COUNT", "3"))

# Adaptive Protocol Switching
ADAPTIVE_PROTOCOL_SWITCHING = os.getenv("ADAPTIVE_PROTOCOL_SWITCHING", "True").lower() == "true"
PROTOCOL_SWITCHING_STRATEGY = os.getenv("PROTOCOL_SWITCHING_STRATEGY", "adaptive")  # adaptive, random, scheduled
MIN_PROTOCOL_SWITCH_INTERVAL = int(os.getenv("MIN_PROTOCOL_SWITCH_INTERVAL", "60"))  # 1 minute
PROTOCOL_HISTORY_SIZE = int(os.getenv("PROTOCOL_HISTORY_SIZE", "100"))
PROTOCOL_CIRCUIT_BREAKER_THRESHOLD = int(os.getenv("PROTOCOL_CIRCUIT_BREAKER_THRESHOLD", "3"))
PROTOCOL_CIRCUIT_BREAKER_RESET_TIME = int(os.getenv("PROTOCOL_CIRCUIT_BREAKER_RESET_TIME", "300"))  # 5 minutes

# Cryptographic Acceleration
PREFERRED_ACCELERATION = os.getenv("PREFERRED_ACCELERATION", "best")  # best, aes_ni, avx2, avx512, openssl, cuda, none

# Multi-path TCP Settings
USE_MULTIPATH_TCP = os.getenv("USE_MULTIPATH_TCP", "False").lower() == "true"
MAX_PATHS = int(os.getenv("MAX_PATHS", "3"))
PATH_TIMEOUT = float(os.getenv("PATH_TIMEOUT", "10.0"))

# Enhanced GFW Evasion
ADVANCED_TRAFFIC_MODELING = os.getenv("ADVANCED_TRAFFIC_MODELING", "True").lower() == "true"
ENABLE_DECOY_TRAFFIC = os.getenv("ENABLE_DECOY_TRAFFIC", "False").lower() == "true"
DECOY_TRAFFIC_RATIO = float(os.getenv("DECOY_TRAFFIC_RATIO", "0.1"))  # 10% decoy traffic

# QUIC settings
QUIC_MAX_DATAGRAM_SIZE = int(os.getenv("QUIC_MAX_DATAGRAM_SIZE", "1350"))
QUIC_IDLE_TIMEOUT = int(os.getenv("QUIC_IDLE_TIMEOUT", "60"))
QUIC_CONGESTION_WINDOW_INITIAL = int(os.getenv("QUIC_CONGESTION_WINDOW_INITIAL", "10"))
QUIC_ENABLE_0RTT = os.getenv("QUIC_ENABLE_0RTT", "True").lower() == "true"
QUIC_USE_RETRY = os.getenv("QUIC_USE_RETRY", "True").lower() == "true"
QUIC_STATELESS_RETRY = os.getenv("QUIC_STATELESS_RETRY", "True").lower() == "true"
QUIC_PORT = int(os.getenv("QUIC_PORT", "8444"))
DEFAULT_QUIC_PORT = QUIC_PORT  # Alias for backward compatibility

# TLS settings
TLS_CERT_FILE = os.getenv("TLS_CERT_FILE", "certs/server.crt")
TLS_KEY_FILE = os.getenv("TLS_KEY_FILE", "certs/server.key")

# Deployment settings
MULTI_GATEWAY_ENABLED = os.getenv("MULTI_GATEWAY_ENABLED", "False").lower() == "true"

# Load config from file if exists
CONFIG_FILE = os.getenv("CONFIG_FILE", "config/config.json")

def load_config() -> Dict[str, Any]:
    """
    Load configuration from file.
    
    Returns:
        Configuration dictionary
    """
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
            return config
        except Exception as e:
            logging.error(f"Failed to load config file: {str(e)}")
    
    return {}

# Load config from file
file_config = load_config()

# Override variables with file config
globals().update(file_config)

def get_config() -> Dict[str, Any]:
    """
    Get the full configuration.
    
    Returns:
        Configuration dictionary
    """
    # Filter out non-uppercase variables and built-ins
    config = {
        key: value for key, value in globals().items()
        if key.isupper() and not key.startswith('_')
    }
    return config 