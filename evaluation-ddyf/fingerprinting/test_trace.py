import sys
import os
import subprocess
import time
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.append(str(_HERE))
import probe
import puts

class Config:
    def prober(self): return "/tmp/tlspuffin_w540"
    def task_prefix(self): return []
    @property
    def timeout(self): return 10

cfg = Config()
trace = "/home/lhirschi/ddyf_experiments/2026-06-10--wolfssl-5.1.1-1cfpp-5.1.1-5.2.0--00-28-23--0/objective/20260609-222823872-19ebecd509e4b007.trace"
port = 27001

def test_version(ver):
    print(f"--- Testing {ver} ---")
    p = probe.launch(cfg, "wolfssl", ver, port)
    time.sleep(2)
    sig = probe.pooled_sig(cfg, trace, port, n_pool=3, dom=2)
    print(f"Result for {ver}: {sig}")
    probe.kill(p)
    time.sleep(1)

os.environ["VENDOR_DIR"] = "/home/lhirschi/FP_3/vendor"
test_version("5.1.1")
test_version("5.2.0")
