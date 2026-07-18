import subprocess
import os

pairs = [
    ("wolfssl510", "wolfssl511"),
    ("wolfssl511", "wolfssl520"),
    ("wolfssl520", "wolfssl521"),
    ("wolfssl521", "wolfssl530"),
    ("wolfssl552", "wolfssl553"),
    ("wolfssl576", "wolfssl580"),
    ("wolfssl580", "wolfssl582"),
    ("wolfssl582", "wolfssl584"),
    ("wolfssl590", "wolfssl591"),
]

def launch(a, b):
    title = f"hunt-{a}-{b}"
    print(f"Launching {title}...")
    cmd = [
        "target/release/tlspuffin",
        "--cores", "0-31", # use all cores
        "differential-experiment", a, b,
        "-t", title,
        "-d", "Targeted TLS 1.3 + Bit-level hunt"
    ]
    env = dict(os.environ, FP_V13_ONLY="1")
    # We'll run them sequentially but give them more time
    try:
        subprocess.run(["timeout", "1200"] + cmd, env=env) # 20 mins each
    except Exception as e:
        print(f"Failed {title}: {e}")

for a, b in pairs:
    launch(a, b)
