import socket

HOST = "0.0.0.0"
PORT = 3000


# First ClientHello: cipher TLS_AES_256_GCM_SHA384, empty key_share
client_hello_1 = bytes.fromhex("160303006e0100006a03030101010101010101010101010101010101010101010101010101010101010101200303030303030303030303030303030303030303030303030303030303030303000213020100001f000a000400020018000d0006000404010804003300020000002b0003020304")

# Second ClientHello: cipher TLS_AES_128_GCM_SHA256, with secp384r1 key share
client_hello_2 = bytes.fromhex("16030300d3010000cf030301010101010101010101010101010101010101010101010101010101010101012003030303030303030303030303030303030303030303030303030303030303030002130101000084000a000400020018000d00060004040108040033006700650018006104533ee5bf40ec2d67988b77f317489bb6df952925c709fc0381111a5956f2d758110e59d3d7c1729e2c0d70eaf773e6120116426de2436a2f5fdd7fe54faf952b04fd13f516ce627f89d2019d4c8796959e4333c7065b496ca634d5dc63bde91f002b0003020304")


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.connect((HOST, PORT))
    print(f"[+] Connected to {HOST}:{PORT}")

    # --- Round 1: trigger HelloRetryRequest ---

    sock.sendall(client_hello_1)
    print(f"[>] Sent first ClientHello ({len(client_hello_1)} bytes)")

    hrr = sock.recv(1024)
    print(f"[<] Received HRR ({len(hrr)} bytes): {hrr.hex()}")

    # --- Round 2: full handshake ---

    sock.sendall(client_hello_2)
    print(f"[>] Sent second ClientHello ({len(client_hello_2)} bytes)")

    server_hello = sock.recv(1024)
    print(f"[<] Received ServerHello ({len(server_hello)} bytes): {server_hello.hex()}")