"""
High-speed inspection tools using native Python libraries.
Mimics "Terminal" capabilities (grep, od, objdump) without Ghidra overhead.
"""
import os
import re
import mmap
import logging
from typing import List, Dict, Any, Optional

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
from elftools.elf.elffile import ELFFile

from ..config import GHIDRA_SAFE_DIR

# Tool Annotations
readOnlyHint = True
idempotentHint = True

logger = logging.getLogger(__name__)

# --- Helper: Security ---
def validate_path(binary_path: str) -> Optional[Dict[str, Any]]:
    """Strict path validation reusing existing logic."""
    try:
        abs_path = os.path.abspath(binary_path)
        if not os.path.exists(abs_path):
            return {"error": f"File not found: {binary_path}"}
        
        if GHIDRA_SAFE_DIR:
            safe_dir = os.path.abspath(GHIDRA_SAFE_DIR)
            real_binary = os.path.realpath(abs_path)
            real_safe = os.path.realpath(safe_dir)
            if not real_binary.startswith(real_safe) or real_binary == real_safe:
                return {"error": f"Access denied: {binary_path}"}
        return None
    except Exception as e:
        return {"error": str(e)}

# --- TOOL 1: search_strings (Grep) ---
def search_strings(binary_path: str, pattern: str, min_length: int = 4) -> List[Dict[str, Any]]:
    """
    Search for strings matching a regex pattern in the binary file.
    Uses mmap for high speed O(n) scanning.
    """
    err = validate_path(binary_path)
    if err: return [err]

    results = []
    try:
        regex = re.compile(pattern.encode('utf-8'))
        
        with open(binary_path, 'rb') as f:
            # Use mmap for large file efficiency
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                for match in regex.finditer(mm):
                    val = match.group().decode('utf-8', 'ignore')
                    if len(val) >= min_length:
                        results.append({
                            "offset": match.start(),
                            "value": val,
                            "context": f"0x{match.start():x}"
                        })
                        if len(results) >= 1000: # Safety limit
                            break
    except Exception as e:
        return [{"error": f"Search failed: {str(e)}"}]
    
    return results

# --- TOOL 2: read_bytes (Od/Hexdump) ---
def read_bytes(binary_path: str, offset: int, length: int) -> Dict[str, Any]:
    """
    Read raw bytes from the binary at specified offset.
    Returns hex string.
    """
    err = validate_path(binary_path)
    if err: return err

    if length > 1024:
        return {"error": "Length too large. Max 1024 bytes."}

    try:
        with open(binary_path, 'rb') as f:
            f.seek(offset)
            data = f.read(length)
            return {
                "offset": offset,
                "length": len(data),
                "hex": data.hex(),
                "ascii": "".join(chr(b) if 32 <= b <= 126 else "." for b in data)
            }
    except Exception as e:
        return {"error": str(e)}

# --- TOOL 3: list_sections (Readelf) ---
def list_sections(binary_path: str) -> List[Dict[str, Any]]:
    """
    List binary sections using pefile (Windows) or pyelftools (Linux).
    """
    err = validate_path(binary_path)
    if err: return [err]

    results = []
    try:
        # Try PE first
        try:
            pe = pefile.PE(binary_path)
            for section in pe.sections:
                results.append({
                    "name": section.Name.decode('utf-8', 'ignore').strip('\x00'),
                    "raw_db_size_hex": hex(section.SizeOfRawData),
                    "virt_addr_hex": hex(section.VirtualAddress),
                    "entropy": section.get_entropy()
                })
            pe.close()
            return results
        except pefile.PEFormatError:
            pass # Not a PE

        # Try ELF
        with open(binary_path, 'rb') as f:
            try:
                elf = ELFFile(f)
                for section in elf.iter_sections():
                    results.append({
                        "name": section.name,
                        "size_hex": hex(section['sh_size']),
                        "addr_hex": hex(section['sh_addr']),
                        "type": section['sh_type']
                    })
                return results
            except Exception:
                pass # Not an ELF
        
        return [{"error": "Unknown binary format (Not PE or ELF)"}]

    except Exception as e:
        return [{"error": str(e)}]

# --- TOOL 4: disassemble_preview (Objdump/Capstone) ---
def disassemble_preview(binary_path: str, offset: int, length: int = 64, arch: str = "x64") -> List[Dict[str, Any]]:
    """
    Disassemble a small chunk of bytes using Capstone.
    Supported architectures: x86, x64, arm, thumb.
    """
    err = validate_path(binary_path)
    if err: return [err]

    try:
        with open(binary_path, 'rb') as f:
            f.seek(offset)
            code = f.read(length)

        # Setup Capstone
        if arch == "x64":
            md = Cs(CS_ARCH_X86, CS_MODE_64)
        elif arch == "x86":
            md = Cs(CS_ARCH_X86, CS_MODE_32)
        elif arch == "arm":
            md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        else:
            return [{"error": f"Unsupported arch: {arch}"}]

        insns = []
        for i in md.disasm(code, offset):
            insns.append({
                "address": f"0x{i.address:x}",
                "mnemonic": i.mnemonic,
                "op_str": i.op_str,
                "bytes": i.bytes.hex()
            })
        return insns

    except Exception as e:
        return [{"error": str(e)}]
