#!/usr/bin/env python3
"""Launch ONE vendored PUT version as a live TCP server, to test fingerprint_probe against.

The pipeline's probing scripts start these servers internally; this exposes the same thing as a
standalone foreground target so you can point the live prober at it:

    # terminal 1: start an OpenSSL 3.6.2 server on :4433
    python3 serve.py --put openssl --version 3.6.2 --port 4433
    # terminal 2: identify it
    python3 fingerprint_probe.py --host 127.0.0.1 --port 4433 --put openssl wolfssl --json

Runs until Ctrl-C. The server is the stack's stock example server (OpenSSL `s_server`, WolfSSL
example `server`) launched via build_live_matrix.server_argv -- exactly what the matrix/validate
stages probe, so a target started here behaves identically.
"""
import argparse
import sys
import time

import probe
import puts


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    puts.add_put_arg(ap)
    ap.add_argument("--version", required=True, help="dotted version, e.g. 3.6.2 or 5.9.0")
    ap.add_argument("--port", type=int, default=4433, help="localhost port to listen on")
    puts.add_common_args(ap, only={"repo_root", "vendor_dir", "cores"})
    args = ap.parse_args()
    put = args.put
    cfg = puts.resolve(args)

    # dotted -> vendor dir name, e.g. ('openssl','3.6.2') -> 'openssl362'
    ver = put + args.version.replace(".", "")
    if ver not in cfg.versions(put):
        sys.exit(f"no vendored server for {put} {args.version} ({ver}) under {cfg.vendor}; "
                 f"build it with setup.sh or build_{put}*.sh")

    srv = probe.launch(cfg, put, ver, args.port)
    if not probe.wait_listen(args.port):
        srv.terminate()
        sys.exit(f"{ver} server failed to start listening on :{args.port}")
    print(f"[serve] {put} {args.version} ({ver}) listening on 127.0.0.1:{args.port}  (Ctrl-C to stop)",
          flush=True)
    try:
        while srv.poll() is None:
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        probe.kill(srv)
        print("\n[serve] stopped", flush=True)


if __name__ == "__main__":
    main()
