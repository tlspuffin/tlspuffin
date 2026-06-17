import subprocess
import time

t0 = time.time()
r = subprocess.run(["/tmp/tlspuffin_w540", "tcp", "/home/lhirschi/ddyf_experiments/2026-06-10--wolfssl-5.1.1-1cfpp-5.1.1-5.2.0--00-28-23--0/objective/20260609-222823872-19ebecd509e4b007.trace", "--port", "27001", "--host", "127.0.0.1", "--json"], capture_output=True, text=True, timeout=10)
print(f"Time: {time.time() - t0}s")
