import sys
import os
import subprocess
import time
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.append(str(_HERE))
import probe

class Config:
    def prober(self): return "/tmp/tlspuffin_w540"
    def task_prefix(self): return []
    @property
    def timeout(self): return 10

cfg = Config()
trace = "/home/lhirschi/ddyf_experiments/2026-06-10--wolfssl-5.1.1-1cfpp-5.1.1-5.2.0--00-28-23--0/objective/20260609-222823872-19ebecd509e4b007.trace"
port = 27001

p = probe.launch(cfg, "wolfssl", "5.1.1", port)
time.sleep(2)
try:
    r = subprocess.run(["/tmp/tlspuffin_w540", "tcp", trace, "--host", "127.0.0.1", "--port", str(port), "--json"], capture_output=True, text=True, timeout=10)
    print("FINISHED in time")
    print(r.stdout[:500])
except subprocess.TimeoutExpired as e:
    print("TIMEOUT!")
    print(e.stdout[:500] if e.stdout else "No stdout")
    print(e.stderr[:500] if e.stderr else "No stderr")
probe.kill(p)
