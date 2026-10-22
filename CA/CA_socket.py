# Author: Maya Thabet October 22nd 2026
import CA
import json
import socket
import struct
import traceback

def send_json(sock, data):
    msg = json.dumps(data).encode()
    length = struct.pack(">I", len(msg))
    sock.sendall(length + msg)


def recv_all(sock, n):
    data = b""

    while len(data) < n:
        packet = sock.recv(n - len(data))

        if not packet:
            return None

        data += packet

    return data


def recv_json(sock):
    raw_len = recv_all(sock, 4)

    if not raw_len:
        return None

    msg_len = struct.unpack(">I", raw_len)[0]

    data = recv_all(sock, msg_len)

    return json.loads(data.decode())

print("Starting CA ...",flush=True)
ca_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

ca_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

ca_socket.bind(("0.0.0.0", 5000))

ca_socket.listen()
print("CA listening on port 5000...",flush=True)

while True:
    import os
    import psutil

    os.sched_setaffinity(0, {0})
    print("CPU Affinity:", os.sched_getaffinity(0))

    p = psutil.Process(os.getpid())

    try:
     p.nice(-20) 
     print("Priority:", p.nice())
    except psutil.AccessDenied:
     print("Permission denied: could not set high priority.")
    
    print("Waiting for connection...",flush=True)

    conn, addr = ca_socket.accept()

    print(f"Connected by {addr} , {conn}",flush=True)

    CA_ALG=CA.choose_algorithm("CA")
    CA.Generate_PQ_Signature_Keys(CA_ALG)
    CA_CRT=CA.CA_Issue_Self_signed_crt(CA_ALG)

    req=recv_json(conn)
    if req is None:
        raise ValueError("No CSR received from ICA")
    
    ICA_CSR=req["CSR"]
    ICA_CRT =CA.CA_Issue_ICA_CRT(ICA_CSR)

    send_json(conn,{
        "Info": "ICA_CRT",
        "CA_crt":CA_CRT,
        "CRT":ICA_CRT})

   