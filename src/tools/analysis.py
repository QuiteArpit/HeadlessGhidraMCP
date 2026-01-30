"""
Analysis tools for Ghidra MCP server.
Binary analysis, folder scanning, batch processing.
"""
import os
import glob
from typing import List, Optional, Dict, Any, Literal
from dataclasses import dataclass, asdict
from mcp.server.fastmcp import Context
from mcp.types import ToolAnnotations

from ..server import mcp
from ..analyzer import analyze_single_binary
from ..response_utils import make_response, make_error

# Type definitions for clarity
StatusType = Literal["analyzed", "cached", "error", "exception", "unknown"]


@dataclass
class BinaryResult:
    """Result for a single binary analysis."""
    path: str
    name: str
    status: StatusType
    functions: Optional[int] = None
    error: Optional[str] = None
    
    
    def __repr__(self) -> str:
        return f"BinaryResult(name={self.name!r}, status={self.status!r})"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dict, omitting None values."""
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class BatchResult:
    """Result for batch analysis operations."""
    total: int
    analyzed: int
    cached: int
    errors: int
    binaries: List[Dict[str, Any]]
    folder: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dict, omitting None values."""
        return {k: v for k, v in asdict(self).items() if v is not None}


class BatchProcessor:
    """
    Handles batch processing of binary files.
    Encapsulates all statistics tracking and error handling.
    """
    
    def __init__(self, files: List[str], ctx: Optional[Context] = None):
        self.files = files
        self.ctx = ctx
        self.total = len(files)
        self.analyzed = 0
        self.cached = 0
        self.errors = 0
        self.binaries: List[BinaryResult] = []
    
    def process(self) -> BatchResult:
        """
        Process all files in the batch.
        Returns a complete BatchResult with all statistics.
        """
        if self.total == 0:
            return self._create_result()
        
        # Report initial progress
        self._report_progress(0)
        
        for i, path in enumerate(self.files):
            self._process_single(i, path)
            self._report_progress(i + 1)
        
        self._log_completion()
        return self._create_result()
    
    def _process_single(self, index: int, path: str) -> None:
        """Process a single binary file."""
        filename = os.path.basename(path)
        if not filename:
            filename = f"file_{index}"
        
        self._log(f"[{index + 1}/{self.total}] Analyzing: {filename}")
        
        try:
            result = analyze_single_binary(path)
            
            # Validate result type
            if not isinstance(result, dict):
                raise TypeError(f"analyze_single_binary returned {type(result)}, expected dict")
            
            # Process based on result content
            binary_result = self._classify_result(path, filename, result)
            
        except (KeyboardInterrupt, SystemExit):
            # Always propagate these
            raise
        except Exception as e:
            # Handle unexpected exceptions by creating an exception result
            binary_result = BinaryResult(
                path=path,
                name=filename,
                status="exception",
                error=f"Unexpected error: {str(e)}"
            )
        
        # Unified Flow: Append and update counters for ALL outcomes
        self.binaries.append(binary_result)
        self._update_counters(binary_result, filename)
    
    def _classify_result(self, path: str, filename: str, result: Dict[str, Any]) -> BinaryResult:
        """
        Classify analysis result and create BinaryResult.
        
        Priority order:
        1. Explicit error in result
        2. Status field (cached, analyzed)
        3. Unknown/unexpected status
        """
        # Check for explicit error first
        if "error" in result:
            return BinaryResult(
                path=path,
                name=filename,
                status="error",
                error=result["error"]
            )
        
        # Extract common fields
        status = result.get("status", "unknown")
        binary_name = result.get("binary_name", filename)
        func_count = result.get("functions_count")
        
        # Validate function count if status indicates success
        if status in ("cached", "analyzed"):
            if func_count is None:
                self._log(f"WARNING: {binary_name} has status '{status}' but missing functions_count")
                func_count = 0
            elif not isinstance(func_count, int) or func_count < 0:
                self._log(f"WARNING: {binary_name} has invalid functions_count: {func_count}")
                func_count = 0
        
        # Create result based on status
        if status == "cached":
            return BinaryResult(
                path=path,
                name=binary_name,
                status="cached",
                functions=func_count
            )
        elif status == "analyzed":
            return BinaryResult(
                path=path,
                name=binary_name,
                status="analyzed",
                functions=func_count
            )
        else:
            # Unknown status
            return BinaryResult(
                path=path,
                name=binary_name,
                status="unknown",
                error=f"Unexpected status: {status}"
            )
    
    def _update_counters(self, binary_result: BinaryResult, filename: str) -> None:
        """Update statistics counters and log based on result status."""
        status = binary_result.status
        
        if status == "analyzed":
            self.analyzed += 1
            self._log(f"Finished {filename}")
            
        elif status == "cached":
            self.cached += 1
            # Cached results are silent by default
            
        elif status == "error":
            self.errors += 1
            self._log(f"ERROR analyzing {filename}: {binary_result.error}")
            
        elif status == "exception":
            self.errors += 1
            self._log(f"EXCEPTION analyzing {filename}: {binary_result.error}")
            
        elif status == "unknown":
            self.errors += 1
            self._log(f"WARNING: Unknown status for {filename}: {binary_result.error}")
            
        else:
            # Unexpected status literal
            self.errors += 1
            self._log(f"ERROR: Unexpected status '{status}' for {filename}")

    def _create_result(self) -> BatchResult:
        """Create final BatchResult from accumulated data."""
        return BatchResult(
            total=self.total,
            analyzed=self.analyzed,
            cached=self.cached,
            errors=self.errors,
            binaries=[b.to_dict() for b in self.binaries]
        )
    
    def _report_progress(self, current: int) -> None:
        """Report progress if context is available."""
        if self.ctx and self.total > 0:
            self.ctx.report_progress(current, self.total)
    
    def _log(self, message: str) -> None:
        """Log message if context is available."""
        if self.ctx:
            self.ctx.info(message)
    
    def _log_completion(self) -> None:
        """Log final completion message."""
        msg = (
            f"Batch analysis complete. "
            f"Analyzed: {self.analyzed}, "
            f"Cached: {self.cached}, "
            f"Errors: {self.errors}"
        )
        self._log(msg)


# Tool functions

@mcp.tool(annotations=ToolAnnotations(idempotentHint=True))
def analyze_binary(binary_path: str, force: bool = False) -> str:
    """
    Analyzes a binary using Ghidra and saves the results to a JSON file.
    Uses cache if available (set force=True to re-analyze).
    
    Args:
        binary_path: Path to the binary file to analyze
        force: If True, ignores cache and re-analyzes the binary
    
    Returns:
        JSON response with analysis results or error
    """
    try:
        result = analyze_single_binary(binary_path, force)
        
        if not isinstance(result, dict):
            return make_error(
                f"Invalid result type from analyzer: {type(result)}",
                code="INTERNAL_ERROR"
            )
        
        if "error" in result:
            return make_error(result["error"], code=result.get("code", "ANALYSIS_ERROR"))
        
        return make_response(data=result)
        
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as e:
        return make_error(f"Unexpected error: {str(e)}", code="SYSTEM_ERROR")


@mcp.tool(annotations=ToolAnnotations(idempotentHint=True))
def analyze_folder(
    folder_path: str,
    extensions: Optional[List[str]] = None,
    ctx: Optional[Context] = None
) -> str:
    """
    Analyze all binaries in a folder recursively.
    
    Args:
        folder_path: Absolute or relative path to the directory to scan
        extensions: List of file extensions to include (e.g., [".exe", ".dll"])
                   Defaults to [".exe", ".dll", ".so", ".dylib", ".bin", ".elf"]
        ctx: MCP context for progress reporting and logging (optional)
    
    Returns:
        JSON string containing BatchResult with:
        - folder: Path to the analyzed folder
        - total: Total number of files found
        - analyzed: Number of newly analyzed files
        - cached: Number of files loaded from cache
        - errors: Number of files that failed analysis
        - binaries: List of results for each binary
    
    Error Codes:
        - NOT_DIRECTORY: Provided path is not a directory
        - SCAN_ERROR: Failed to scan directory (permissions, etc.)
    """
    # Validate directory
    if not os.path.isdir(folder_path):
        return make_error(f"Not a directory: {folder_path}", code="NOT_DIRECTORY")
    
    # Default extensions
    if extensions is None:
        extensions = [".exe", ".dll", ".so", ".dylib", ".bin", ".elf"]
    
    # Scan for files
    try:
        all_files = []
        for ext in extensions:
            pattern = os.path.join(folder_path, f"**/*{ext}")
            all_files.extend(glob.glob(pattern, recursive=True))
        
        # Remove duplicates and sort
        all_files = sorted(list(set(all_files)))
        
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as e:
        return make_error(f"Failed to scan folder: {str(e)}", code="SCAN_ERROR")
    
    # Handle empty results
    if len(all_files) == 0:
        if ctx:
            ext_str = ", ".join(extensions)
            ctx.info(f"No files found in {folder_path} matching extensions: {ext_str}")
        
        result = BatchResult(
            total=0,
            analyzed=0,
            cached=0,
            errors=0,
            binaries=[],
            folder=folder_path
        )
        return make_response(data=result.to_dict())
    
    # Log start
    if ctx:
        ctx.info(f"Found {len(all_files)} files in {folder_path}. Starting analysis...")
    
    # Process batch
    processor = BatchProcessor(all_files, ctx)
    result = processor.process()
    
    # Add folder info
    result.folder = folder_path
    
    return make_response(data=result.to_dict())


@mcp.tool(annotations=ToolAnnotations(idempotentHint=True))
def analyze_binaries(
    binary_paths: List[str],
    ctx: Optional[Context] = None
) -> str:
    """
    Analyze multiple binaries at once.
    
    Args:
        binary_paths: List of binary file paths to analyze
        ctx: MCP context for progress reporting
    
    Returns:
        JSON response with batch analysis results
    """
    # Handle empty list
    if len(binary_paths) == 0:
        result = BatchResult(
            total=0,
            analyzed=0,
            cached=0,
            errors=0,
            binaries=[]
        )
        return make_response(data=result.to_dict())
    
    # Log start
    if ctx:
        ctx.info(f"Starting batch analysis of {len(binary_paths)} binaries...")
    
    # Process batch
    processor = BatchProcessor(binary_paths, ctx)
    result = processor.process()
    
    return make_response(data=result.to_dict())
