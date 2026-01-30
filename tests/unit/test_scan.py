import os
import pytest
from unittest.mock import patch, MagicMock
from src.tools.system import scan_folder

@pytest.fixture
def mock_scandir(tmp_path):
    # Create fake files
    (tmp_path / "test.exe").write_bytes(b"MZ\x90\x00")
    (tmp_path / "test.elf").write_bytes(b"\x7fELF")
    (tmp_path / "test.txt").write_text("Hello")
    (tmp_path / "subdir").mkdir()
    return str(tmp_path)

def test_scan_folder(mock_scandir):
    # Patch GHIDRA_SAFE_DIR in src.config since src.tools.system imports it from there
    with patch("src.config.GHIDRA_SAFE_DIR", None): 
        response = scan_folder(mock_scandir)
        assert '"status": "success"' in response
        assert '"test.exe"' in response
        assert '"PE (Windows)"' in response
        assert '"test.elf"' in response
        assert '"ELF (Linux)"' in response
        assert '"test.txt"' in response
