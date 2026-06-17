import subprocess
import json
import time

# Known/Likely OpenSSL: inria.fr, belenios.org, wikipedia.org, mozilla.org
# Known/Likely Custom (BoringSSL/s2n): google.com, cloudflare.com, amazon.com
urls = [
    # Academic/Research
    "inria.fr",
    "https://www.belenios.org/",
    "https://vote.belenios.org/v3/",
    "mit.edu",
    "stanford.edu",
    "cmu.edu",
    "berkeley.edu",
    "cam.ac.uk",
    "ox.ac.uk",
    "ethz.ch",
    
    # Tech Giants / CDNs
    "cloudflare.com",
    "google.com",
    "github.com",
    "amazon.com",
    "apple.com",
    "microsoft.com",
    "fastly.com",
    "akamai.com",
    "cdn.net",
    
    # Media / Social
    "wikipedia.org",
    "duckduckgo.com",
    "reddit.com",
    "twitter.com",
    "facebook.com",
    "netflix.com",
    "youtube.com",
    "vimeo.com",
    "twitch.tv",
    "spotify.com",
    "instagram.com",
    
    # Dev / Tools
    "stackoverflow.com",
    "protonmail.com",
    "gitlab.com",
    "bitbucket.org",
    "mozilla.org",
    "docker.com",
    "kubernetes.io",
    "nginx.com",
    "apache.org",
    "openssl.org"
]

print(f"{'Target URL':<30} | {'Status':<15} | {'Library (Cluster)':<30} | {'Confidence'}")
print("-" * 95)

for url in urls:
    # --repeat 30 to match the 30-trial consistency filter used in lab building.
    # --delay 1.0 to respect rate limits.
    cmd = [
        "python3", "evaluation-ddyf/fingerprinting/fingerprint_probe.py",
        "--put", "openssl", "wolfssl",
        "--reference-dir", "evaluation-ddyf/fingerprinting/reproduced",
        "--url", url,
        "--delay", "1.0",
        "--repeat", "30",
        "--retries", "2",
        "--timeout", "8.0",
        "--json"
    ]
    
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=1200)
        data = None
        try:
            idx = res.stdout.find('{')
            if idx != -1:
                data = json.loads(res.stdout[idx:])
        except json.JSONDecodeError:
            pass
        
        if data:
            status = data.get("status", "error")
            put = data.get("put", "N/A")
            cluster = data.get("cluster")
            
            # Differentiate the "Unknown" states
            if status == "unknown":
                # Check if it was a total rejection (all models failed to connect or returned empty)
                all_rejected = True
                for p in data.get("per_put", []):
                    if p.get("status") not in ("connection_error", "no_tls_response", "probe_failed"):
                        all_rejected = False
                if all_rejected:
                    status = "REJECTED"
                else:
                    status = "OTHER_STACK"
            
            if cluster and len(cluster) > 0 and len(cluster[0]) > 0:
                cluster_str = cluster[0][0] + (f" (+{len(cluster[0])-1})" if len(cluster[0]) > 1 else "")
            else:
                cluster_str = "None"
            
            lib_info = f"{put} [{cluster_str}]" if status == "identified" else "N/A"
            conf = data.get("confidence", "N/A")
            
            print(f"{url:<30} | {status:<15} | {lib_info:<30} | {conf}")
        else:
            print(f"{url:<30} | {'PARSE_ERR':<15} | {'N/A':<30} | {'N/A'}")
            
    except subprocess.TimeoutExpired:
        print(f"{url:<30} | {'TIMEOUT':<15} | {'N/A':<30} | {'N/A'}")
    except Exception as e:
        print(f"{url:<30} | {'ERR':<15} | {str(e)[:30]:<30} | {'N/A'}")

