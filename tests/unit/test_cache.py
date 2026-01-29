import os
import json
import tempfile
import pytest
from unittest.mock import patch
from src import cache

@pytest.fixture
def temp_cache_dir():
    with tempfile.TemporaryDirectory() as tmp:
        # Patch the constants in cache module
        with patch('src.cache.INDEX_FILE', os.path.join(tmp, 'index.json')), \
             patch('src.cache.CACHE_DIR', os.path.join(tmp, 'cache')):
            os.makedirs(os.path.join(tmp, 'cache'), exist_ok=True)
            yield tmp

def test_load_save_index(temp_cache_dir):
    """Verify index creation and persistence."""
    # Should start empty or create new
    idx = cache.load_index()
    assert idx == {"version": "1.0", "binaries": {}}
    
    # Modify and save
    idx["binaries"]["abc"] = {"name": "test"}
    cache.save_index(idx)
    
    # Load again
    idx2 = cache.load_index()
    assert idx2["binaries"]["abc"]["name"] == "test"

def test_get_file_hash():
    """Verify SHA256 hashing."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"hello world")
        f.close()
        try:
            # sha256("hello world") = b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
            # first 16 chars: b94d27b9934d3e08
            h = cache.get_file_hash(f.name)
            assert h == "b94d27b9934d3e08"
        finally:
            os.unlink(f.name)

def test_get_cached_analysis(temp_cache_dir):
    """Verify cache lookup."""
    # Create fake cache file
    file_hash = "1234567890abcdef"
    cache_path = os.path.join(temp_cache_dir, 'cache', f"{file_hash}.json")
    with open(cache_path, 'w') as f:
        json.dump({"test": True}, f)
    
    # Lookup
    found = cache.get_cached_analysis(file_hash)
    assert found == cache_path
    
    # Lookup non-existent
    assert cache.get_cached_analysis("invalid") is None
