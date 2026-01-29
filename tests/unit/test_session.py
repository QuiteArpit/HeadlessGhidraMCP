import pytest
from src import session

def test_session_management():
    """Verify session tracking."""
    # Start fresh
    session.clear_session_data()
    
    # Add item
    session.add_to_session("/tmp/test", "hash123", "/tmp/test.json", 10, 5)
    
    # Verify added
    binaries = session.get_all_session_binaries()
    assert "/tmp/test" in binaries
    
    info = session.get_from_session("/tmp/test")
    assert info["hash"] == "hash123"
    assert info["functions"] == 10
    
    # Verify listing
    assert "/tmp/test" in session.get_all_session_binaries()
    
    # Clear session
    session.clear_session_data()
    assert len(session.get_all_session_binaries()) == 0
