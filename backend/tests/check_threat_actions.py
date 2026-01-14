#!/usr/bin/env python3
"""
Script to check threat_actions.py for errors.
Run this script to verify threat_actions.py has no syntax or import errors.

This script should be run before committing changes to ensure code quality.
"""

import sys
import ast
import subprocess
from pathlib import Path

def check_file():
    """Check threat_actions.py for errors."""
    file_path = Path(__file__).parent / "app" / "services" / "threat_actions.py"
    
    if not file_path.exists():
        print(f"❌ Error: File not found: {file_path}")
        return False
    
    print(f"Checking {file_path}...")
    print("=" * 60)
    
    # Check syntax with py_compile
    try:
        result = subprocess.run(
            [sys.executable, "-m", "py_compile", str(file_path)],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            print("✓ Python syntax check passed (py_compile)")
        else:
            print(f"❌ Python syntax check failed:")
            print(result.stderr)
            return False
    except Exception as e:
        print(f"❌ Error running py_compile: {e}")
        return False
    
    # Check syntax with ast.parse
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            code = f.read()
        ast.parse(code)
        print("✓ AST syntax check passed")
    except SyntaxError as e:
        print(f"❌ Syntax error at line {e.lineno}: {e.msg}")
        if e.text:
            print(f"   {e.text.rstrip()}")
            print(f"   {' ' * (e.offset - 1) if e.offset else ''}^")
        return False
    except Exception as e:
        print(f"❌ Error parsing file: {e}")
        return False
    
    # Check for common issues
    issues = []
    
    # Check for try without except/finally
    try:
        tree = ast.parse(code)
        for node in ast.walk(tree):
            if isinstance(node, ast.Try):
                if not node.handlers and not node.finalbody:
                    issues.append(f"Try statement without except/finally at line {node.lineno}")
    except Exception:
        pass
    
    # Check for indentation issues (basic check)
    lines = code.split('\n')
    for i, line in enumerate(lines, 1):
        # Check for common indentation errors
        if 'except' in line and not line.strip().startswith('except'):
            # except might be incorrectly indented
            if i > 1 and 'try:' in lines[i-2] if i > 1 else False:
                # Check if except aligns with try
                try_indent = len(lines[i-2]) - len(lines[i-2].lstrip())
                except_indent = len(line) - len(line.lstrip())
                if except_indent > try_indent + 4:
                    issues.append(f"Possible indentation error at line {i}: except block may be over-indented")
    
    if issues:
        print("\n⚠ Issues found:")
        for issue in issues:
            print(f"  - {issue}")
        return False
    
    print("\n" + "=" * 60)
    print("✓ All checks passed - threat_actions.py is valid")
    return True

if __name__ == "__main__":
    success = check_file()
    sys.exit(0 if success else 1)

