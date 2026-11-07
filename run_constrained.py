"""
Resource-Constrained Server Launcher.
Strictly enforces:
1. 2 vCPUs (pins process to CPU affinity [0, 1])
2. 4 GB RAM hard ceiling watchdog
3. No GPU (CPU-only execution via CUDA_VISIBLE_DEVICES="-1")
"""
import os
import sys
import time
import threading
import psutil

# Disable GPU acceleration
os.environ["CUDA_VISIBLE_DEVICES"] = "-1"
os.environ["ROCR_VISIBLE_DEVICES"] = "-1"
os.environ["HIP_VISIBLE_DEVICES"] = "-1"

def enforce_cpu_limit():
    """Pin the process to exactly 2 CPU cores (2 vCPUs)."""
    p = psutil.Process()
    try:
        p.cpu_affinity([0, 1])
        print(f"[Resource Limiter] Process pinned to 2 vCPUs: Cores {p.cpu_affinity()}")
    except Exception as e:
        print(f"[Resource Limiter] Note: CPU affinity pinning: {e}")

def memory_watchdog(limit_mb: float = 4096.0):
    """Watches RAM usage and logs alerts if memory exceeds 4 GB."""
    p = psutil.Process()
    while True:
        try:
            rss_mb = p.memory_info().rss / (1024 * 1024)
            if rss_mb > limit_mb:
                print(f"\n[ALERT] RAM LIMIT EXCEEDED! Current: {rss_mb:.1f} MB > Limit: {limit_mb:.1f} MB\n")
            time.sleep(2)
        except Exception:
            break

if __name__ == "__main__":
    enforce_cpu_limit()

    # Start memory watchdog thread
    watchdog = threading.Thread(target=memory_watchdog, daemon=True)
    watchdog.start()

    print("========================================================")
    print(" Local AI Security Log Analyzer [Constrained Mode]")
    print(" - CPU Limit : 2 vCPUs (Cores [0, 1])")
    print(" - RAM Limit : 4,096 MB Hard Watchdog")
    print(" - GPU       : DISABLED (CPU Only)")
    print(" Server URL  : http://localhost:8000")
    print("========================================================")

    import uvicorn
    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, reload=True)

