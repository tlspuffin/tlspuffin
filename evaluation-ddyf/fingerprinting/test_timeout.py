import sys
from pathlib import Path
_HERE = Path(__file__).resolve().parent
sys.path.append(str(_HERE))
import probe
import puts

class DummyConfig:
    def prober(self): return "target/release/tlspuffin"
    def task_prefix(self): return []
    @property
    def timeout(self): return 2

cfg = DummyConfig()
trace = "evaluation-ddyf/fingerprinting/reference/wolfssl/probes/20260609-222826816-e4c49967a70ff749.trace"
port = 27000

print(f"Testing pooled_sig against hanging server on port {port}...")
sig = probe.pooled_sig(cfg, trace, port, n_pool=3, dom=2)
print(f"Result: {sig}")
