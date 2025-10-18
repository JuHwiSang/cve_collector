from __future__ import annotations

from cve_collector.config.token_utils import hash_token_for_namespace


def test_hash_token_for_namespace_returns_consistent_hash():
    """Test that same token always produces same hash."""
    token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
    hash1 = hash_token_for_namespace(token)
    hash2 = hash_token_for_namespace(token)
    assert hash1 == hash2


def test_hash_token_for_namespace_different_tokens_produce_different_hashes():
    """Test that different tokens produce different hashes."""
    token1 = "ghp_token_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    token2 = "ghp_token_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    hash1 = hash_token_for_namespace(token1)
    hash2 = hash_token_for_namespace(token2)
    assert hash1 != hash2


def test_hash_token_for_namespace_returns_correct_length():
    """Test that hash has the requested prefix length."""
    token = "ghp_test_token"
    hash_12 = hash_token_for_namespace(token, prefix_length=12)
    hash_8 = hash_token_for_namespace(token, prefix_length=8)
    hash_16 = hash_token_for_namespace(token, prefix_length=16)

    assert len(hash_12) == 12
    assert len(hash_8) == 8
    assert len(hash_16) == 16


def test_hash_token_for_namespace_returns_hex_characters():
    """Test that hash contains only valid hex characters."""
    token = "ghp_test_token_with_special_chars!@#$%"
    hash_value = hash_token_for_namespace(token)

    # Should only contain 0-9, a-f
    assert all(c in "0123456789abcdef" for c in hash_value)


def test_hash_token_for_namespace_different_prefix_lengths_share_prefix():
    """Test that longer hash starts with shorter hash."""
    token = "ghp_consistent_token"
    hash_8 = hash_token_for_namespace(token, prefix_length=8)
    hash_12 = hash_token_for_namespace(token, prefix_length=12)

    # hash_12 should start with hash_8
    assert hash_12.startswith(hash_8)
