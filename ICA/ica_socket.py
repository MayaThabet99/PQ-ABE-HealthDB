# Author: Maya Thabet October 22nd 2026
import base64
import csv
import os
import time
import ICA
import json
import socket
import struct
import traceback
from pqcrypto.sign import (
    ml_dsa_44, ml_dsa_65, ml_dsa_87,
    sphincs_sha2_128f_simple, sphincs_sha2_192f_simple, sphincs_sha2_256f_simple
)
ALGORITHMS = {
     ml_dsa_44: "ml_dsa_44",
     ml_dsa_65: "ml_dsa_65",
     ml_dsa_87: "ml_dsa_87",
     sphincs_sha2_128f_simple: "sphincs_sha2_128f_simple",
     sphincs_sha2_192f_simple: "sphincs_sha2_192f_simple",
     sphincs_sha2_256f_simple: "sphincs_sha2_256f_simple"}

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

 print("ICA starting...")




 ca_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
 ca_sock.connect(("ca", 5000))
 print("Connected to CA!")

#--------Generate ICA_CRT------------#
 ICA_ALG=ICA.choose_algorithm("Personal_ICA")

 ICA.Generate_PQ_Signature_Keys(ICA_ALG)

 ICA_PK, ICA_SK, _ =ICA.Read_Keys()

 ICA_CSR= ICA.Generate_ICA_CSR(ICA_PK,ICA_SK,ICA_ALG)


 send_json(ca_sock, {
    "Info": "ICA_CSR",
    "CSR": ICA_CSR
 })


 REC = recv_json(ca_sock)

 if REC is None:
    raise ValueError("No CRT received from CA")

 ICA_CRT=REC["CRT"]
 CA_CRT=REC["CA_crt"]
 print("ICA_CRT receved")


 ica_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

 ica_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

 ica_socket.bind(("0.0.0.0", 5001))

 ica_socket.listen()

 print("ICA: listening on port 5001...", flush=True)

 print("ICA: waiting for SERVER connection...", flush=True)
 conn, addr = ica_socket.accept()

 print(f"ICA: SERVER connected from {addr}", flush=True) 

 csrreq = recv_json(conn)

 if csrreq is None:
     raise ValueError("No CSR received from server")
 
 filename = "server_Cert.pem"
 server_CRT=ICA.ICA_Issue_Certificate(csrreq["CSR"],ICA_CRT,filename)
 send_json(conn,{
    "INFO":"Server crt",
    "ICA_CRT":ICA_CRT,
    "CA_CRT":CA_CRT,
    "crt":server_CRT
 })
 print("Sleeping for a sec")
 time.sleep(1)
 print("ICA: attempting to connect to CL:5003...", flush=True)
 cl_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
 cl_socket.connect(("cl", 5003))

 print("ICA: connected to CL!", flush=True)

 filename = "cl_Cert.pem"
 csrreq2 = recv_json(cl_socket)
 cl_CRT=ICA.ICA_Issue_Certificate(csrreq2["CSR"],ICA_CRT,filename)
 send_json(cl_socket,{
    "INFO":"Server crt",
    "ICA_CRT":ICA_CRT,
    "CA_CRT":CA_CRT,
    "crt":cl_CRT
 })




 