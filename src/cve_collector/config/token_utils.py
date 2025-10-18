from __future__ import annotations

import hashlib


def hash_token_for_namespace(token: str, prefix_length: int = 12) -> str:
    """Hash a token (e.g., GitHub token) to create a safe namespace identifier.

    Uses SHA3-256 and returns the first N characters of the hex digest.
    This prevents storing raw tokens in cache keys while maintaining uniqueness.

    Args:
        token: The token to hash (e.g., GitHub personal access token)
        prefix_length: Number of hex characters to use from the hash (default: 12)

    Returns:
        Hashed prefix suitable for use as a namespace identifier

    Example:
        >>> hash_token_for_namespace("ghp_1234567890abcdef", prefix_length=12)
        'a1b2c3d4e5f6'
    """
    hash_obj = hashlib.sha3_256(token.encode("utf-8"))
    return hash_obj.hexdigest()[:prefix_length]
