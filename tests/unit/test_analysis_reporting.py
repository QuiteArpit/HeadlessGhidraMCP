"""
Test analysis tools with mocked Context to verify reporting.
"""
import os
import pytest
from unittest.mock import MagicMock, patch

from src.tools import analysis

@patch("src.tools.analysis.analyze_single_binary")
def test_analyze_binaries_reporting(mock_analyze, tmp_path):
    # Setup
    files = ["/tmp/a.exe", "/tmp/b.exe"]
    mock_analyze.side_effect = [
        {"status": "analyzed", "binary_name": "a.exe", "functions_count": 10},
        {"error": "Failed", "code": "FAIL"}
    ]
    
    mock_ctx = MagicMock()
    
    # Run
    res = analysis.analyze_binaries(files, ctx=mock_ctx)
    
    # Verify Context Calls
    # 1. Info: Starting
    mock_ctx.info.assert_any_call("Starting batch analysis of 2 binaries...")
    
    # 1.5 Progress: 0/2 (Start)
    mock_ctx.report_progress.assert_any_call(0, 2)
    
    # 2. Progress: 1/2 (Finished Item 1)
    mock_ctx.report_progress.assert_any_call(1, 2)
    mock_ctx.info.assert_any_call("[1/2] Analyzing: a.exe")
    
    # 3. Success Info
    mock_ctx.info.assert_any_call("Finished a.exe")
    
    # 4. Progress: 2/2 (Finished Item 2)
    mock_ctx.report_progress.assert_any_call(2, 2)
    mock_ctx.info.assert_any_call("[2/2] Analyzing: b.exe")
    
    # 5. Error Info (Fixed from ctx.error)
    mock_ctx.info.assert_any_call("ERROR analyzing b.exe: Failed")
    
    # Complete
    mock_ctx.info.assert_any_call("Batch analysis complete. Analyzed: 1, Cached: 0, Errors: 1")
