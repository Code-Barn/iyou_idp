"""
Crypto utilities for DID verification using Rust bridge.
"""
from typing import Optional


def verify_bridge() -> Optional[str]:
    """
    Verify that the Rust crypto bridge is accessible.
    
    Returns:
        Optional[str]: Message from Rust bridge if successful, None otherwise.
    """
    try:
        # Explicit import from iyou_idp._crypto as per pyproject.toml
        from iyou_idp._crypto import hello_from_bin
        return hello_from_bin()
    except ImportError as e:
        print(f"Rust bridge not available: {e}")
        return None
    except Exception as e:
        print(f"Error calling Rust bridge: {e}")
        return None
