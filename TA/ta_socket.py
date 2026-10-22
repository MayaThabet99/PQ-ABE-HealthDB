# Author: Maya Thabet October 22nd 2026
import base64
import csv
import os
import random
import string
import TA
import json
import socket
import time
import struct
import traceback
from charm.core.engine.util import objectToBytes
import pickle
import struct
import time
import psycopg2

def send_pickle(sock, data):
    msg = pickle.dumps(data)

    length = struct.pack(">I", len(msg))

    sock.sendall(length + msg)

def recv_pickle(sock):
    raw_len = recv_all(sock, 4)

    if not raw_len:
        return None

    msg_len = struct.unpack(">I", raw_len)[0]

    data = recv_all(sock, msg_len)

    return pickle.loads(data) 

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

 print("TA starting...")

 Creat_ABE_curve_time=TA.Write_ABE_SETUP()

 ABE_group,CP_ABE,ABE_public_key,ABE_master_key=TA.Read_ABE_SETUP()
 req_id= ''.join(random.choices(string.ascii_uppercase, k=32))

 ta_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
 ta_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
 ta_socket.bind(("0.0.0.0", 5002))

 ta_socket.listen()

 print("TA listening on port 5002...",flush=True)
 conn, addr = ta_socket.accept()

 attributes =recv_json(conn)
 end=time.perf_counter()
 if attributes is None:
     raise ValueError("No attributes received from server")
 start=attributes["Start_time"]

 attributes_connection_time=(end-start)*1000

 abe_ct,aes_key,ABE_ENC_TIME,policy_gen=TA.Encrypt_intermediate_key_With_ABE(ABE_group, attributes["col"], CP_ABE, ABE_public_key, req_id)
     
 SK_att,att_size,SK_KEYGEN=TA.gen_SK_att(attributes["Access_flag"],attributes["speciality"],attributes["role"],req_id,ABE_public_key,ABE_master_key,CP_ABE)
     
 POFP_Token = TA.create_token() + req_id.encode('ascii')


 serialized_pk = base64.b64encode(objectToBytes(ABE_public_key, ABE_group)).decode()

 serialized_sk = base64.b64encode(objectToBytes(SK_att, ABE_group)).decode()

 serialized_ct = base64.b64encode(objectToBytes(abe_ct, ABE_group)).decode()

 #--------POFP-------#
 start=time.perf_counter()
 send_json(conn, {
    "ABE_public_key": serialized_pk,
    "SK_att": serialized_sk,
    "abe_ct": serialized_ct,
    "Start_time":start,
    "POFP_Token":  base64.b64encode(POFP_Token).decode()})



 POFP_DATA =recv_json(conn)





 if POFP_DATA is None:
     raise ValueError("No POFP_DATA received from server")
 
 POFP_ENC_FLAG,POFP_SIG,POFP_MSSG_SIG,POFP_DEC=TA.decrypt_verification(aes_key, POFP_DATA, POFP_Token)
 
 if POFP_ENC_FLAG:
     cur,con=TA.connection_to_DB()
     reencryptiontimestart_time=time.perf_counter()
     encrypted_data=TA.re_encryption(cur, attributes["col"], aes_key, attributes["Patient_id"])
     reencryptiontimeend_time=time.perf_counter()
     reencryptiontime=(reencryptiontimeend_time-reencryptiontimestart_time)*1000
     send_json(conn,{"POFP_SIG":POFP_SIG,
                 "POFP_MSSG_SIG":POFP_MSSG_SIG,
                 "POFP_ENC_FLAG":POFP_ENC_FLAG,
                 "encrypted_data": base64.b64encode(encrypted_data.encode("utf-8")).decode()})

     CSV_FILE = "ta.csv"
     if not os.path.exists(CSV_FILE):
       with open(CSV_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
          "Creat_ABE_curve_time",
          "ABE Encryption Time",
          "Attribute Private Key Generation",
          "Attribute Size",
          "Policy Gen",
          "POFP_DEC",
          "attributes_connection_time",
          "Re-encryption Time"])
 
     with open(CSV_FILE, "a", newline="") as f:
         writer = csv.writer(f)
         writer.writerow([  
             f"{Creat_ABE_curve_time:.3f}", 
             f"{ABE_ENC_TIME:.3f}",
             f"{SK_KEYGEN:.3f}",
             f"{att_size:.3f}",
             f"{policy_gen:.3f}",
             f"{POFP_DEC:.3f}",
             f"{attributes_connection_time:.3f}",
             f"{reencryptiontime:.3f}"])


     con.commit()
     cur.close()
 else:print("POFP Verification Failed, Aborting Re-encryption")

 
 
 
 
