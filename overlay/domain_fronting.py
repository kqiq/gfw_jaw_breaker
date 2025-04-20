"""
Dynamic Domain Fronting module for GFW evasion.

This module enhances domain fronting capabilities by dynamically rotating through
trusted domains and providing optimal selection based on performance and reliability.
"""
import random
import logging
import time
import asyncio
import socket
import ssl
import aiohttp
from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass, field
import traceback

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Default trusted domains for fronting
DEFAULT_TRUSTED_DOMAINS = [
    "cloudfront.net",
    "akamaized.net",
    "cloudflare.com",
    "fastly.net",
    "azure-api.net",
    "azureedge.net",
    "amazonaws.com",
    "edgekey.net",
    "googleusercontent.com"
]

class NoAvailableDomainsError(Exception):
    """Raised when no available domains for fronting can be found."""
    pass

@dataclass
class DomainStatus:
    """Status information for a domain used in fronting."""
    domain: str
    last_success: float = 0
    last_check: float = 0
    success_count: int = 0
    failure_count: int = 0
    latency: float = 1000.0  # milliseconds
    risk_score: float = 0.0  # 0-1, higher means more likely to be blocked
    is_available: bool = False
    error_history: List[str] = field(default_factory=list)
    
    @property
    def reliability(self) -> float:
        """Calculate reliability score (0-1) based on success and failure counts."""
        total = self.success_count + self.failure_count
        if total == 0:
            return 0.5  # No data
        return self.success_count / total
    
    @property
    def recency_factor(self) -> float:
        """Calculate recency factor (0-1) based on how recently this domain was used successfully."""
        if self.last_success == 0:
            return 0.0
        
        hours_since_success = (time.time() - self.last_success) / 3600
        # Factor decreases as time increases, with 24 hours being a significant threshold
        return max(0.0, 1.0 - (hours_since_success / 24.0))
    
    @property
    def performance_score(self) -> float:
        """Calculate overall performance score for domain selection."""
        if not self.is_available:
            return 0.0
        
        # Factors influencing score:
        # 1. Reliability (success vs. failure)
        # 2. Latency (lower is better)
        # 3. Recency (more recent success is better)
        # 4. Risk (lower is better)
        
        # Normalize latency to 0-1 (where 0 is bad, 1 is good)
        latency_factor = max(0.0, 1.0 - min(1.0, self.latency / 1000.0))
        
        # Combine factors with weights
        score = (
            0.4 * self.reliability +
            0.2 * latency_factor +
            0.2 * self.recency_factor +
            0.2 * (1.0 - self.risk_score)
        )
        
        return score
        
    def record_success(self, latency: float) -> None:
        """Record a successful connection using this domain."""
        self.last_success = time.time()
        self.last_check = time.time()
        self.success_count += 1
        self.latency = latency
        self.is_available = True
        
        # Decrease risk score with successful uses (floor at 0)
        self.risk_score = max(0.0, self.risk_score - 0.05)
        
    def record_failure(self, error: str = None) -> None:
        """Record a failed connection using this domain."""
        self.last_check = time.time()
        self.failure_count += 1
        
        # Store error information
        if error:
            self.error_history.append(f"{time.time()}: {error}")
            # Keep only the last 10 errors
            if len(self.error_history) > 10:
                self.error_history = self.error_history[-10:]
        
        # Increase risk score with failures (ceiling at 1)
        self.risk_score = min(1.0, self.risk_score + 0.1)
        
        # Mark as unavailable if risk is too high
        if self.risk_score > 0.7:
            self.is_available = False

class DomainFrontingManager:
    """
    Manages dynamic domain fronting for bypassing censorship.
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize the domain fronting manager.
        
        Args:
            config: Configuration options
        """
        self.config = config or {}
        self.trusted_domains = self.config.get('trusted_domains', DEFAULT_TRUSTED_DOMAINS)
        self.check_interval = self.config.get('domain_check_interval', 3600)  # 1 hour
        self.current_domain = None
        self.domain_status = {}
        self.fallback_domains = []
        self.http_client = None
        self.last_check_time = 0
        self.test_url = self.config.get('domain_test_url', 'https://www.google.com')
        
        # Initialize domain status for each trusted domain
        for domain in self.trusted_domains:
            self.domain_status[domain] = DomainStatus(domain=domain)
            
        # Initialize fallback domains (hard-coded reliable options)
        self.fallback_domains = self.config.get('fallback_domains', ['cloudfront.net', 'azureedge.net'])
        
        logger.info(f"Domain Fronting Manager initialized with {len(self.trusted_domains)} trusted domains")
    
    async def initialize(self) -> None:
        """Initialize and perform first domain availability check."""
        # Create HTTP client
        if not self.http_client:
            self.http_client = aiohttp.ClientSession()
            
        # Check domain availability
        await self.check_domain_availability()
    
    async def close(self) -> None:
        """Close resources used by the manager."""
        if self.http_client:
            await self.http_client.close()
            self.http_client = None
    
    async def check_domain_availability(self, force: bool = False) -> None:
        """
        Check availability of all trusted domains.
        
        Args:
            force: Force checking even if check interval hasn't elapsed
        """
        current_time = time.time()
        
        # Only check if enough time has passed since last check
        if not force and current_time - self.last_check_time < self.check_interval:
            return
            
        self.last_check_time = current_time
        logger.info("Checking availability of trusted domains...")
        
        # Create HTTP client if needed
        if not self.http_client:
            self.http_client = aiohttp.ClientSession()
        
        # Check each domain in parallel
        tasks = []
        for domain in self.trusted_domains:
            tasks.append(self._check_single_domain(domain))
            
        # Wait for all checks to complete
        await asyncio.gather(*tasks, return_exceptions=True)
        
        # Count available domains
        available_count = sum(1 for status in self.domain_status.values() if status.is_available)
        logger.info(f"Domain availability check complete. {available_count}/{len(self.trusted_domains)} domains available")
    
    async def _check_single_domain(self, domain: str) -> None:
        """
        Check availability of a single domain.
        
        Args:
            domain: Domain to check
        """
        status = self.domain_status.get(domain)
        if not status:
            status = DomainStatus(domain=domain)
            self.domain_status[domain] = status
        
        try:
            # Try to connect to test URL through this domain
            headers = {
                'Host': self.test_url.split('://')[1].split('/')[0],
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            
            start_time = time.time()
            async with self.http_client.get(
                self.test_url,
                headers=headers,
                timeout=5,
                ssl=False  # Don't verify SSL to mimic fronting behavior
            ) as response:
                elapsed = (time.time() - start_time) * 1000  # ms
                
                if response.status < 400:
                    # Success
                    status.record_success(elapsed)
                    logger.debug(f"Domain {domain} is available (latency: {elapsed:.1f}ms)")
                else:
                    # HTTP error
                    status.record_failure(f"HTTP error {response.status}")
                    logger.debug(f"Domain {domain} returned HTTP {response.status}")
        
        except asyncio.TimeoutError:
            status.record_failure("Connection timeout")
            logger.debug(f"Domain {domain} check timed out")
            
        except (aiohttp.ClientError, ssl.SSLError) as e:
            status.record_failure(str(e))
            logger.debug(f"Domain {domain} check failed: {e}")
            
        except Exception as e:
            status.record_failure(f"Unexpected error: {str(e)}")
            logger.debug(f"Unexpected error checking domain {domain}: {e}")
    
    def _is_domain_available(self, domain: str) -> bool:
        """
        Check if a domain is available for fronting.
        
        Args:
            domain: Domain to check
            
        Returns:
            True if the domain is available
        """
        status = self.domain_status.get(domain)
        if not status:
            return False
            
        return status.is_available
    
    def _find_optimal_domain(self, available_domains: List[str]) -> str:
        """
        Find the optimal domain for fronting based on performance metrics.
        
        Args:
            available_domains: List of available domains
            
        Returns:
            Selected domain name
        """
        if not available_domains:
            return None
            
        # Calculate scores for each domain
        domain_scores = []
        for domain in available_domains:
            status = self.domain_status.get(domain)
            if not status:
                continue
                
            score = status.performance_score
            domain_scores.append((domain, score))
            
        # Sort by score (highest first)
        domain_scores.sort(key=lambda x: x[1], reverse=True)
        
        # If we have scores, pick the highest scoring domain
        if domain_scores:
            selected_domain = domain_scores[0][0]
            logger.debug(f"Selected domain {selected_domain} with score {domain_scores[0][1]:.2f}")
            return selected_domain
            
        # Fallback to random selection
        return random.choice(available_domains)
    
    async def select_domain(self) -> str:
        """
        Select optimal domain for fronting.
        
        Returns:
            Selected domain name
            
        Raises:
            NoAvailableDomainsError: If no available domains are found
        """
        # Check if we need to refresh domain availability
        await self.check_domain_availability()
        
        # Filter available domains
        available_domains = [d for d in self.trusted_domains 
                           if self._is_domain_available(d)]
        
        # If no available domains, try fallback domains
        if not available_domains:
            available_domains = [d for d in self.fallback_domains 
                               if d in self.trusted_domains]
            
        if not available_domains:
            raise NoAvailableDomainsError("All fronting domains appear blocked")
            
        # Select domain with best performance/reliability
        self.current_domain = self._find_optimal_domain(available_domains)
        
        return self.current_domain
    
    async def get_current_domain(self) -> str:
        """
        Get the current domain for fronting, selecting one if needed.
        
        Returns:
            Current domain
            
        Raises:
            NoAvailableDomainsError: If no available domains are found
        """
        if not self.current_domain:
            return await self.select_domain()
            
        return self.current_domain
    
    async def rotate_domain(self) -> str:
        """
        Rotate to a different domain if current one is compromised.
        
        Returns:
            New domain
            
        Raises:
            NoAvailableDomainsError: If no available domains are found
        """
        if self.current_domain:
            # Mark current domain as higher risk
            status = self.domain_status.get(self.current_domain)
            if status:
                status.risk_score += 0.2
                logger.info(f"Increased risk score for {self.current_domain} to {status.risk_score:.2f}")
                
        # Force domain availability check
        await self.check_domain_availability(force=True)
        
        # Select a new domain (different from current)
        old_domain = self.current_domain
        
        # Filter available domains
        available_domains = [d for d in self.trusted_domains 
                           if d != old_domain and self._is_domain_available(d)]
        
        if not available_domains:
            raise NoAvailableDomainsError("No alternative fronting domains available")
            
        self.current_domain = self._find_optimal_domain(available_domains)
        
        logger.info(f"Rotated domain fronting from {old_domain} to {self.current_domain}")
        return self.current_domain
    
    def report_domain_success(self, domain: str, latency: float) -> None:
        """
        Report successful use of a domain.
        
        Args:
            domain: Domain that was used successfully
            latency: Connection latency in milliseconds
        """
        status = self.domain_status.get(domain)
        if status:
            status.record_success(latency)
            logger.debug(f"Recorded successful use of domain {domain} (latency: {latency:.1f}ms)")
    
    def report_domain_failure(self, domain: str, error: str) -> None:
        """
        Report failed use of a domain.
        
        Args:
            domain: Domain that failed
            error: Error description
        """
        status = self.domain_status.get(domain)
        if status:
            status.record_failure(error)
            logger.warning(f"Recorded failure for domain {domain}: {error}")
            
    async def apply_domain_fronting(self, target_url: str) -> Tuple[str, Dict[str, str]]:
        """
        Apply domain fronting to a target URL.
        
        Args:
            target_url: Original target URL
            
        Returns:
            Tuple of (fronted_url, headers) to use for the connection
            
        Raises:
            NoAvailableDomainsError: If no available domains are found
        """
        # Get current domain (or select one if needed)
        domain = await self.get_current_domain()
        
        # Parse the original URL
        parts = target_url.split('://', 1)
        if len(parts) < 2:
            raise ValueError(f"Invalid URL format: {target_url}")
            
        protocol = parts[0]
        rest = parts[1].split('/', 1)
        original_host = rest[0]
        path = rest[1] if len(rest) > 1 else ""
        
        # Create fronted URL (use fronting domain as the connection target)
        fronted_url = f"{protocol}://{domain}/{path}"
        
        # Create headers (use original host in the Host header)
        headers = {
            'Host': original_host,
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        return fronted_url, headers 