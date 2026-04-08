"""
ZARIS AI Folder Scanner Test
Run this to see the scanner in action
"""

import time
from pathlib import Path
from backend.folder_scanner import FolderScanner, format_scan_result


def run_test():
    print("=" * 50)
    print("ZARIS AI FOLDER SCANNER - TEST")
    print("=" * 50)

    scanner = FolderScanner(quick_mode=True)

    # Scan Downloads folder
    downloads = str(Path.home() / "Downloads")
    print(f"\nScanning: {downloads}")
    print("Please wait...\n")

    start = time.time()
    result = scanner.scan_now([downloads])
    elapsed = time.time() - start

    print(f"Scan completed in {elapsed:.2f} seconds\n")
    print("-" * 50)
    print("SUMMARY:")
    print("-" * 50)
    print(f"  Files: {result.total_files:,}")
    print(f"  Size: {result.total_size_mb:,.2f} MB")
    print(f"  Time: {result.scan_duration_sec:.2f}s\n")

    # Duplicates
    print("DUPLICATES:")
    if result.duplicates:
        for dup in result.duplicates[:5]:
            files_str = ", ".join([Path(f).name[:20] for f in dup["files"][:2]])
            print(f"  - {dup['count']} copies x {dup['size_mb']}MB = {dup['wasted_mb']}MB wasted")
            print(f"    Files: {files_str}...")
        total_wasted = sum(d["wasted_mb"] for d in result.duplicates)
        print(f"  Total wasted: {total_wasted:.1f} MB\n")
    else:
        print("  No duplicates found\n")

    # Suspicious files
    print("SUSPICIOUS FILES:")
    if result.suspicious_files:
        for f in result.suspicious_files[:5]:
            print(f"  - {f['type']} -> {Path(f['path']).name} ({f['size_mb']}MB)")
        print(f"  Total: {len(result.suspicious_files)} suspicious\n")
    else:
        print("  No suspicious files\n")

    # Unused files
    print("UNUSED FILES (90+ days):")
    if result.unused_files:
        for f in result.unused_files[:5]:
            print(f"  - {f['size_mb']}MB, {f['days_unused']} days old -> {Path(f['path']).name}")
        total_unused = sum(f["size_mb"] for f in result.unused_files)
        print(f"  Total unused: {total_unused:.1f} MB\n")
    else:
        print("  No unused files\n")

    # Large files
    print("LARGE FILES (>100MB):")
    if result.large_files:
        for f in result.large_files[:5]:
            print(f"  - {f['size_mb']}MB -> {Path(f['path']).name}")
    else:
        print("  No large files")

    print("\n" + "=" * 50)
    print("TEST COMPLETE")
    print("=" * 50)


if __name__ == "__main__":
    run_test()