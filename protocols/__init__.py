"""
VPN protocols and obfuscation methods.
"""
from typing import Dict, Any, Type

from protocols.shadowsocks_protocol import ShadowsocksProtocol, create_shadowsocks_protocol  
from protocols.vmess_protocol import VMessProtocol, create_vmess_protocol
from protocols.trojan_protocol import TrojanProtocol, create_trojan_protocol

# Protocol registry
PROTOCOLS = {
    'shadowsocks': create_shadowsocks_protocol,
    'vmess': create_vmess_protocol,
    'trojan': create_trojan_protocol,
}

def get_protocol(name: str, config: Dict[str, Any] = None):
    """
    Get a protocol implementation by name.
    
    Args:
        name: Protocol name
        config: Protocol configuration
        
    Returns:
        Protocol instance
    """
    if name not in PROTOCOLS:
        raise ValueError(f"Unknown protocol: {name}")
        
    return PROTOCOLS[name](config)

__all__ = [
    'ShadowsocksProtocol',
    'create_shadowsocks_protocol',
    'VMessProtocol',
    'create_vmess_protocol',
    'TrojanProtocol',
    'create_trojan_protocol',
    'get_protocol',
    'PROTOCOLS'
] 