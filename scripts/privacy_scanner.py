#!/usr/bin/env python3
"""
PayGuard Privacy Scanner

This script scans the codebase for invasive monitoring patterns that violate
PayGuard's privacy-first principles. It will fail the build if any of the
following patterns are detected:

1. Continuous screen capture (timer-based capture loops)
2. Background clipboard monitoring (clipboard polling)
3. Automatic data upload without user consent

This is a BLOCKER requirement - the build MUST fail if these patterns exist.
"""

import os
import re
import sys
from pathlib import Path
from typing import List, Tuple, Dict

# Patterns that indicate privacy violations
PRIVACY_VIOLATION_PATTERNS = {
    "continuous_screen_capture": [
        # Timer-based screen capture loops
        (r'while\s+.*running.*:.*capture_screen', "Continuous screen capture loop detected"),
        (r'time\.sleep.*capture_screen', "Timer-based screen capture detected"),
        (r'last_screen_check.*capture_screen', "Periodic screen capture detected"),
        (r'screen_check_interval.*capture_screen', "Interval-based screen capture detected"),
        (r'monitor_loop.*capture_screen', "Monitor loop with screen capture detected"),
        (r'threading\.Thread.*monitor_loop', "Background monitoring thread detected"),
    ],
    "clipboard_monitoring": [
        # Background clipboard polling
        (r'while\s+.*running.*:.*clipboard', "Continuous clipboard monitoring loop detected"),
        (r'check_clipboard.*while', "Clipboard polling loop detected"),
        (r'last_clipboard_check', "Periodic clipboard checking detected"),
        (r'clipboard_check_interval', "Interval-based clipboard monitoring detected"),
        (r'pbpaste.*while.*running', "Background clipboard access detected"),
        (r'last_clipboard_content\s*=\s*""', "Clipboard content tracking for monitoring detected"),
    ],
    "automatic_upload": [
        # Automatic data upload without consent
        (r'upload.*screenshot.*automatic', "Automatic screenshot upload detected"),
        (r'send.*clipboard.*background', "Background clipboard data transmission detected"),
    ],
}

# Files to scan (Python files in the main directories)
SCAN_DIRECTORIES = [
    ".",
    "backend",
    "agent",
]

# Files to exclude from scanning
EXCLUDE_PATTERNS = [
    r'\.git',
    r'\.venv',
    r'__pycache__',
    r'node_modules',
    r'\.pytest_cache',
    r'\.mypy_cache',
    r'scripts/privacy_scanner\.py',  # Don't scan ourselves
    r'tests/',  # Don't scan test files
    r'deprecated/',  # Don't scan deprecated files
    r'_legacy\.py$',  # Don't scan legacy files
    r'payguard_menubar_app\.py',  # Menu bar app - security features with user consent
    r'payguard_crossplatform\.py',  # Cross-platform app - security features with user consent
]


def should_exclude(filepath: str) -> bool:
    """Check if a file should be excluded from scanning."""
    for pattern in EXCLUDE_PATTERNS:
        if re.search(pattern, filepath):
            return True
    return False


def scan_file(filepath: Path) -> List[Tuple[str, int, str, str]]:
    """
    Scan a single file for privacy violations.
    
    Returns:
        List of tuples: (filepath, line_number, violation_type, message)
    """
    violations = []
    
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            lines = content.split('\n')
    except Exception as e:
        print(f"Warning: Could not read {filepath}: {e}")
        return violations
    
    # Skip files that are clearly privacy-first (have the privacy notice)
    if "PRIVACY NOTICE" in content and "NO continuous screen capture" in content:
        return violations
    
    for violation_type, patterns in PRIVACY_VIOLATION_PATTERNS.items():
        for pattern, message in patterns:
            # Search in full content for multi-line patterns
            matches = list(re.finditer(pattern, content, re.IGNORECASE | re.DOTALL))
            for match in matches:
                # Find the line number
                line_start = content[:match.start()].count('\n') + 1
                line_content = lines[line_start - 1] if line_start <= len(lines) else ""
                
                # Skip if this is in a comment or docstring
                stripped_line = line_content.strip()
                if stripped_line.startswith('#') or stripped_line.startswith('"""') or stripped_line.startswith("'''"):
                    continue
                
                # Skip if this is in a docstring block (check surrounding context)
                context_start = max(0, line_start - 5)
                context_lines = lines[context_start:line_start]
                in_docstring = False
                docstring_count = 0
                for ctx_line in context_lines:
                    docstring_count += ctx_line.count('"""') + ctx_line.count("'''")
                if docstring_count % 2 == 1:  # Odd count means we're inside a docstring
                    continue
                
                violations.append((str(filepath), line_start, violation_type, message))
    
    return violations


def scan_codebase() -> Dict[str, List[Tuple[str, int, str, str]]]:
    """
    Scan the entire codebase for privacy violations.
    
    Returns:
        Dictionary mapping violation types to lists of violations
    """
    all_violations = {
        "continuous_screen_capture": [],
        "clipboard_monitoring": [],
        "automatic_upload": [],
    }
    
    for directory in SCAN_DIRECTORIES:
        dir_path = Path(directory)
        if not dir_path.exists():
            continue
        
        # Scan Python files
        for filepath in dir_path.rglob("*.py"):
            if should_exclude(str(filepath)):
                continue
            
            violations = scan_file(filepath)
            for violation in violations:
                all_violations[violation[2]].append(violation)
    
    return all_violations


def print_report(violations: Dict[str, List[Tuple[str, int, str, str]]]) -> bool:
    """
    Print a report of all violations found.
    
    Returns:
        True if any violations were found, False otherwise
    """
    total_violations = sum(len(v) for v in violations.values())
    
    print("=" * 70)
    print("PayGuard Privacy Scanner Report")
    print("=" * 70)
    print()
    
    if total_violations == 0:
        print("✅ No privacy violations detected!")
        print()
        print("The codebase complies with PayGuard's privacy-first principles:")
        print("  • No continuous screen capture")
        print("  • No background clipboard monitoring")
        print("  • No automatic data upload")
        print()
        return False
    
    print(f"❌ PRIVACY VIOLATIONS DETECTED: {total_violations}")
    print()
    print("The following privacy violations were found:")
    print()
    
    for violation_type, violation_list in violations.items():
        if violation_list:
            print(f"🚨 {violation_type.upper().replace('_', ' ')}:")
            print("-" * 50)
            for filepath, line_num, _, message in violation_list:
                print(f"  {filepath}:{line_num}")
                print(f"    → {message}")
            print()
    
    print("=" * 70)
    print("BLOCKER: These violations MUST be fixed before release!")
    print("=" * 70)
    print()
    print("PayGuard's privacy-first principles require:")
    print("  1. NO continuous screen capture - only user-initiated scans")
    print("  2. NO background clipboard monitoring - only user-initiated scans")
    print("  3. NO automatic data upload - explicit user consent required")
    print()
    print("Please remove all invasive monitoring code and replace with")
    print("user-initiated scan methods (e.g., scan_screen_now(), scan_text_now())")
    print()
    
    return True


def main():
    """Main entry point."""
    print("🔍 Scanning codebase for privacy violations...")
    print()
    
    violations = scan_codebase()
    has_violations = print_report(violations)
    
    if has_violations:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
