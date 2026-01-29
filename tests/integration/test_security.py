import os
import pytest
from unittest.mock import patch
from src.analyzer import analyze_single_binary
from src.config import BASE_DIR

@pytest.fixture
def clean_env():
    """Ensure clean environment for security tests."""
    # Store original
    original_safe_dir = os.environ.get("GHIDRA_SAFE_DIR")
    yield
    # Restore original
    if original_safe_dir:
        os.environ["GHIDRA_SAFE_DIR"] = original_safe_dir
    elif "GHIDRA_SAFE_DIR" in os.environ:
        del os.environ["GHIDRA_SAFE_DIR"]

def test_path_traversal_blocked(clean_env, tmp_path):
    """Verify that access outside safe dir is blocked."""
    # Create a "safe" directory and a "secret" directory
    safe_dir = tmp_path / "safe"
    safe_dir.mkdir()
    secret_dir = tmp_path / "secret"
    secret_dir.mkdir()

    # Create dummy binaries
    safe_bin = safe_dir / "safe.exe"
    safe_bin.write_text("fake binary content")
    
    secret_bin = secret_dir / "secret.exe"
    secret_bin.write_text("fake secret content")

    # Set environment variable
    with patch.dict(os.environ, {"GHIDRA_SAFE_DIR": str(safe_dir)}):
        # Reload config to pick up env var (mocking config value directly might be easier but less integration-y)
        # Note: Since config is imported at module level in analyzer, we need to patch the MODULE variable
        with patch("src.analyzer.GHIDRA_SAFE_DIR", str(safe_dir)):
            
            # 1. Allowed Access
            result = analyze_single_binary(str(safe_bin), force=True)
            # Should fail on 'Ghidra Not Found' or 'cached' or 'analyzed', but NOT 'SECURITY_VIOLATION'
            assert result.get("code") != "SECURITY_VIOLATION"

            # 2. Denied Access (Outside Dir)
            result = analyze_single_binary(str(secret_bin), force=True)
            assert result.get("code") == "SECURITY_VIOLATION"
            assert "Access denied" in result.get("error")

def test_no_safe_dir_allows_all(clean_env, tmp_path):
    """Verify that standard behavior allows any path if env var is unset."""
    any_bin = tmp_path / "any.exe"
    any_bin.write_text("content")

    with patch("src.analyzer.GHIDRA_SAFE_DIR", None):
        result = analyze_single_binary(str(any_bin), force=True)
        # Should proceed (likely fail on ghidra execution if no real ghidra, but pass security check)
        assert result.get("code") != "SECURITY_VIOLATION"
