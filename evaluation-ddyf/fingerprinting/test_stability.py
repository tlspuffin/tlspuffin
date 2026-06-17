import sys
import os
import time
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.append(str(_HERE))
import probe

class Config:
    def prober(self): return "/tmp/tlspuffin_w540"
    def task_prefix(self): return []
    @property
    def timeout(self): return 8

cfg = Config()
trace = "/home/lhirschi/ddyf_experiments/2026-06-10--wolfssl-5.7.2-1cfpp-5.7.0-5.7.2--00-28-23--0/objective/20260610-030101020-89f3023f1631c645.trace"
port = 27001

def test_pacing(ms):
    os.environ["PUFFIN_TCP_IO_SLEEP_MS"] = str(ms)
    print(f"--- Testing pacing {ms}ms ---")
    p = probe.launch(cfg, "wolfssl", "5.1.1", port)
    time.sleep(2)
    sigs = []
    for i in range(10):
        # We call _run_once directly to bypass Counter
        res = probe._run_once(cfg, cfg.prober(), trace, port)
        sigs.append(res[1] if res else "None")
    print(f"Results: {sigs}")
    probe.kill(p)
    time.sleep(1)

os.environ["VENDOR_DIR"] = "/home/lhirschi/FP_3/vendor"
test_pacing(50)
test_pacing(100)
test_pacing(150)
