#!/usr/bin/env python3
"""
Memory stress test application for pressured demo.

This app gradually allocates memory to trigger pressured thresholds:
- Warn at 80% (default)
- Critical at 90% (default)

Usage:
  Set MEMORY_LIMIT_MB environment variable to control target memory.
  Default: 100MB
"""

import os
import time
import sys

def get_memory_limit_mb():
    """Get memory limit from environment or default to 100MB."""
    return int(os.environ.get('MEMORY_LIMIT_MB', '100'))

def allocate_memory_gradually():
    """Gradually allocate memory to trigger OOM warnings."""
    limit_mb = get_memory_limit_mb()
    target_mb = int(limit_mb * 0.95)  # Target 95% to trigger critical

    print(f"Memory Stress Test")
    print(f"==================")
    print(f"Container memory limit: {limit_mb}MB")
    print(f"Target allocation: {target_mb}MB (95%)")
    print(f"This will trigger:")
    print(f"  - WARN at ~{int(limit_mb * 0.80)}MB (80%)")
    print(f"  - CRITICAL at ~{int(limit_mb * 0.90)}MB (90%)")
    print()

    # Store allocated memory blocks
    memory_blocks = []
    block_size_mb = 5  # Allocate 5MB at a time
    block_size_bytes = block_size_mb * 1024 * 1024

    allocated_mb = 0

    print("Starting gradual memory allocation...")
    print()

    while allocated_mb < target_mb:
        try:
            # Allocate a block of memory (filled with zeros to ensure it's actually allocated)
            block = bytearray(block_size_bytes)
            memory_blocks.append(block)
            allocated_mb += block_size_mb

            percentage = (allocated_mb / limit_mb) * 100
            status = "NORMAL"
            if percentage >= 90:
                status = "CRITICAL"
            elif percentage >= 80:
                status = "WARN"

            print(f"[{status:8}] Allocated: {allocated_mb:3}MB / {limit_mb}MB ({percentage:.1f}%)")

            # Wait a bit between allocations to let pressured detect the pressure
            time.sleep(2)

        except MemoryError:
            print(f"MemoryError at {allocated_mb}MB - approaching OOM!")
            break

    print()
    print(f"Reached target allocation: {allocated_mb}MB")
    print("Holding memory for 60 seconds to allow monitoring...")
    print("(Container will likely be OOM-killed soon)")

    # Hold the memory
    for i in range(60):
        time.sleep(1)
        if i % 10 == 0:
            print(f"  Holding... ({i}s)")

    print("Test complete!")

if __name__ == '__main__':
    try:
        allocate_memory_gradually()
    except KeyboardInterrupt:
        print("\nInterrupted by user")
        sys.exit(0)
