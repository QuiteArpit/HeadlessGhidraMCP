#!/usr/bin/env python3
"""
Cleanup script for HeadlessGhidraMCP.
Removes cached files, virtual environment, and analysis output.
"""
import argparse
import shutil
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

TARGETS = {
    "cache": {
        "desc": "__pycache__ directories",
        "paths": ["src/__pycache__", "src/tools/__pycache__", "tests/__pycache__", 
                  "tests/unit/__pycache__", "tests/integration/__pycache__", ".pytest_cache"]
    },
    "venv": {
        "desc": "Virtual environment",
        "paths": [".venv"]
    },
    "output": {
        "desc": "Analysis output",
        "paths": ["analysis_output"]
    }
}

def get_size(path):
    """Get directory size in MB."""
    total = 0
    if os.path.isdir(path):
        for root, dirs, files in os.walk(path):
            for f in files:
                try:
                    total += os.path.getsize(os.path.join(root, f))
                except OSError:
                    pass
    return total / (1024 * 1024)

def clean(targets, dry_run=False):
    """Clean specified targets."""
    for target in targets:
        if target not in TARGETS:
            print(f"[warn] Unknown target: {target}")
            continue
        
        info = TARGETS[target]
        print(f"\n[{target}] {info['desc']}")
        
        for rel_path in info["paths"]:
            full_path = os.path.join(SCRIPT_DIR, rel_path)
            if os.path.exists(full_path):
                size = get_size(full_path)
                if dry_run:
                    print(f"  Would delete: {rel_path} ({size:.2f} MB)")
                else:
                    shutil.rmtree(full_path, ignore_errors=True)
                    print(f"  Deleted: {rel_path} ({size:.2f} MB)")
            else:
                print(f"  Skipped: {rel_path} (not found)")

def main():
    parser = argparse.ArgumentParser(
        description="Clean HeadlessGhidraMCP project files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python clean.py                  # CLEAN EVERYTHING EXCEPT .venv (Default)
  python clean.py --all            # Remove everything including .venv
  python clean.py --venv           # Remove only .venv
  python clean.py --output         # Remove only analysis output
  python clean.py --dry-run        # Show what would be deleted
        """
    )
    parser.add_argument("--cache", action="store_true", help="Remove __pycache__")
    parser.add_argument("--venv", action="store_true", help="Remove .venv")
    parser.add_argument("--output", action="store_true", help="Remove analysis_output")
    parser.add_argument("--all", action="store_true", help="Remove everything")
    parser.add_argument("--soft", action="store_true", help="Remove everything EXCEPT .venv (Default)")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be deleted")
    
    args = parser.parse_args()
    
    targets = []
    
    # Logic for target selection
    if args.all:
        targets = list(TARGETS.keys())
    elif args.venv:
        # User explicitly targets venv
        targets = ["venv", "cache", "output"] if args.soft else ["venv"]
        if args.cache: targets.append("cache")
        if args.output: targets.append("output")
    elif args.cache or args.output:
        # Granular selection
        if args.cache: targets.append("cache")
        if args.output: targets.append("output")
    else:
        # Default behavior (or explicit --soft): Clean everything except venv
        targets = ["cache", "output"]
    
    if args.dry_run:
        print("[dry-run] No files will be deleted\n")
    
    clean(targets, dry_run=args.dry_run)
    print("\n[done]")

if __name__ == "__main__":
    main()
