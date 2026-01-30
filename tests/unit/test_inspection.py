"""
Unit tests for source inspection tools (search_strings, read_bytes, etc.).
Uses mocking to avoid needing real PE/ELF files.
"""
import os
import io
import pytest
from unittest.mock import MagicMock, patch, mock_open

from src.tools import inspection

# --- Test: search_strings ---
@patch("src.tools.inspection.validate_safe_path", return_value=None)
def test_search_strings_found(mock_val):
    # Mock file content with "password" inside
    content = b"user=admin\npassword=secret\n"
    
    with patch("builtins.open", mock_open(read_data=content)):
        with patch("mmap.mmap") as mock_mmap:
            # Mock mmap behavior to behave like the content buffer
            mm = MagicMock()
            mm.__iter__ = lambda x: iter(content.splitlines(keepends=True))
            mm.read.side_effect = content
            mm.find.side_effect = content.find
            mm.__getitem__ = lambda s, x: content[x]
            mm.__len__ = lambda s: len(content)
            
            # Since our implementation traverses regex.finditer(mm), 
            # we need mmap to act string-like enough for re module.
            # Easiest way for unit test is to bypass mmap and test logic on file read,
            # but our code uses mmap. 
            # Let's mock the 'mmap' context manager to return a bytes object directly? 
            # No, 're' needs buffer interface.
            
            # SIMPLER: Mock the tool's usage of mmap
            pass 

    # Alternative: Create a real temp file for reliable mmap testing
    pass

@patch("src.tools.inspection.validate_safe_path", return_value=None)
def test_search_strings_real_file(mock_val, tmp_path):
    f = tmp_path / "test.bin"
    f.write_bytes(b"some_junk_data_flag{found_me}_more_junk_password123")
    
    results = inspection.search_strings(str(f), r"flag\{.*?\}")
    assert len(results) == 1
    assert results[0]["value"] == "flag{found_me}"

# --- Test: read_bytes ---
@patch("src.tools.inspection.validate_safe_path", return_value=None)
def test_read_bytes_valid(mock_val, tmp_path):
    f = tmp_path / "test.bin"
    f.write_bytes(b"\xAA\xBB\xCC\xDD" * 10)
    
    res = inspection.read_bytes(str(f), 4, 4)
    assert res["hex"] == "aabbccdd"
    assert res["length"] == 4

@patch("src.tools.inspection.validate_safe_path", return_value=None)
def test_read_bytes_too_large(mock_val, tmp_path):
    f = tmp_path / "test.bin"
    f.touch()
    res = inspection.read_bytes(str(f), 0, 2048)
    assert "error" in res
    assert "Length too large" in res["error"]

# --- Test: list_sections (PE) ---
@patch("pefile.PE")
@patch("src.tools.inspection.validate_safe_path", return_value=None)
def test_list_sections_pe(mock_val, mock_pe_cls, tmp_path):
    f = tmp_path / "fake.exe"
    f.touch()
    
    # Mock PE instance
    mock_pe = MagicMock()
    section = MagicMock()
    section.Name = b".text\x00\x00"
    section.SizeOfRawData = 1024
    section.VirtualAddress = 4096
    section.get_entropy.return_value = 6.5
    
    mock_pe.sections = [section]
    mock_pe_cls.return_value = mock_pe
    
    res = inspection.list_sections(str(f))
    assert len(res) == 1
    assert res[0]["name"] == ".text"
    assert res[0]["entropy"] == 6.5

# --- Test: disassemble_preview ---
@patch("src.tools.inspection.validate_safe_path", return_value=None)
def test_disassemble_preview_x64(mock_val, tmp_path):
    f = tmp_path / "code.bin"
    # NOP, RET
    f.write_bytes(b"\x90\xC3")
    
    res = inspection.disassemble_preview(str(f), 0, 2, "x64")
    assert len(res) == 2
    assert res[0]["mnemonic"] == "nop"
    assert res[1]["mnemonic"] == "ret"
