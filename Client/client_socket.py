# Author: Maya Thabet October 22nd 2026
import base64
import json
import socket
import struct
import traceback
import user
import pickle
import struct
import time
import csv
import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from asn1crypto import x509, pem
from charm.core.engine.util import bytesToObject
from charm.toolbox.pairinggroup import PairingGroup
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
ABE_group = PairingGroup('MNT224')
CP_ABE = CPabe_BSW07(ABE_group)
from pqcrypto.sign import (
    ml_dsa_44, ml_dsa_65, ml_dsa_87,
    sphincs_sha2_128f_simple, sphincs_sha2_192f_simple, sphincs_sha2_256f_simple)
from pqcrypto.kem import ml_kem_512

OID_TO_ALGORITHM = {
    "2.16.840.1.101.3.4.3.17": ml_dsa_44,
    "2.16.840.1.101.3.4.3.18": ml_dsa_65,
    "2.16.840.1.101.3.4.3.19": ml_dsa_87,
    "2.16.840.1.101.3.4.3.21": sphincs_sha2_128f_simple,
    "2.16.840.1.101.3.4.3.23": sphincs_sha2_192f_simple,
    "2.16.840.1.101.3.4.3.25": sphincs_sha2_256f_simple
}
ALGORITHMS = {
     ml_dsa_44: "ml_dsa_44",
     ml_dsa_65: "ml_dsa_65",
     ml_dsa_87: "ml_dsa_87",
     sphincs_sha2_128f_simple: "sphincs_sha2_128f_simple",
     sphincs_sha2_192f_simple: "sphincs_sha2_192f_simple",
     sphincs_sha2_256f_simple: "sphincs_sha2_256f_simple"}


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

def secure_recv(sock, aes_key):
    raw_len = recv_all(sock, 4)

    if not raw_len:
        return None

    msg_len = struct.unpack(">I", raw_len)[0]

    msg = recv_all(sock, msg_len)
    ENC_START=time.perf_counter()

    encrypted = json.loads(msg.decode())

    iv = bytes.fromhex(encrypted["IV"])
    tag = bytes.fromhex(encrypted["Tag"])
    ciphertext = bytes.fromhex(encrypted["Ciphertext"])

    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=iv)

    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    Enc_end=time.perf_counter()


    return json.loads(plaintext.decode()),(Enc_end - ENC_START)*1000

def secure_send(sock, data, aes_key):

    ENC_START=time.perf_counter()
    plaintext = json.dumps(data).encode("utf-8")

    iv = get_random_bytes(12)

    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=iv)

    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    message = {
        "IV": iv.hex(),
        "Tag": tag.hex(),
        "Ciphertext": ciphertext.hex()
    }

    msg = json.dumps(message).encode()

    length = struct.pack(">I", len(msg))
    Enc_end=time.perf_counter()


    sock.sendall(length + msg)
    return (Enc_end - ENC_START)*1000


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


print("Client starting...")
print("Connecting to server...")
server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


iteration=0
while iteration<1:
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
    
    try:
     print("Client starting...")
     cl_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
     cl_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
     cl_socket.bind(("0.0.0.0", 5003))
     cl_socket.listen()

     print("CL: waiting for ICA connection...", flush=True)
     conn, addr = cl_socket.accept()
     print(f"CL: ICA connected from {addr}", flush=True)

     print(f"""#############run {iteration + 1}#############""")
     username = "drnagy"
     password = "drnagy"
     role = "Doctor"

     cl_alg=user.choose_algorithm("client")

     cl_keygen_start=time.perf_counter()
     user.Generate_PQ_Signature_Keys(cl_alg,username)
     cl_keygen_end=time.perf_counter()


     cl_pk,cl_sk,_ =user.Read_Keys(username)

     cl_csr=user.Generate_CSR(cl_alg,username)

     
     

     print("Connected to ICA!")
     send_json(conn,{
          "CSR":cl_csr})
     crt_rec=recv_json(conn)
     if crt_rec is None:
            raise ValueError("No crt received fromo ICA")

     CL_CRT=crt_rec["crt"]
     ICA=crt_rec["ICA_CRT"]
     CA=crt_rec["CA_CRT"]

    
     server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)    
     server_sock.connect(("server", 8000))
     print("Connected to server!")

     


#-------Start TLS Handshake---------#
     TLS_handshake_start=time.perf_counter()

     send_json(server_sock,{
          "hello": "hello"})
     

     hello = recv_json(server_sock)
     send_json(server_sock,{
          "certificate": CL_CRT})

     server_kem_pk = bytes.fromhex(
        hello["kem_public_key"])
    
     kem_sig = base64.b64decode(
        hello["kem_signature"])
    
     CRT=hello["certificate"]

     if isinstance(CRT, str):
      CRT = CRT.encode("utf-8")
     if pem.detect(CRT):
      _, _, server_der_bytes = pem.unarmor(CRT)
     else:
      server_der_bytes = CRT

     server_cert = x509.Certificate.load(server_der_bytes)

     if isinstance(ICA, str):
      ICA = ICA.encode("utf-8")

     if pem.detect(ICA):
      _, _, ICA_der_bytes = pem.unarmor(ICA)
     else:
      ICA_der_bytes = ICA

     ICA_cert = x509.Certificate.load(ICA_der_bytes)

     if isinstance(CA, str):
      CA = CA.encode("utf-8")

     if pem.detect(CA):
      _, _, CA_der_bytes = pem.unarmor(CA)
     else:
      CA_der_bytes = CA

     CA_cert = x509.Certificate.load(CA_der_bytes)
    
     verify_chain_start=time.perf_counter()
     crt_flag=user.verify_Server_crt(server_cert,ICA_cert,CA_cert)
     verify_chain_end=time.perf_counter()
    
    
     if not crt_flag:
       raise ValueError("Server certificate is not verified")
    
     server_PK=server_cert["tbs_certificate"]["subject_public_key_info"]["public_key"].native
    
     server_Signature_algorithm_oid=server_cert["tbs_certificate"]["subject_public_key_info"]["algorithm"]["algorithm"].native
     server_Signature_algorithm=OID_TO_ALGORITHM[server_Signature_algorithm_oid]
    
     verify_server_start=time.perf_counter()
     if not server_Signature_algorithm.verify(server_PK,server_kem_pk,kem_sig):
        raise ValueError("Server KEM  signature not verified")
     verify_server_end=time.perf_counter()
    

     ciphertext, shared_secret = ml_kem_512.encrypt(server_kem_pk)
    
     send_json(server_sock,{
       "KEM_Ciphertext": ciphertext.hex()})
     Latency_start = time.perf_counter()
     _=secure_send(server_sock, {
        "username": username,
        "password":password,
        "role": role
     }, shared_secret)
   
     print("login credintials sent!")

#---------login token-----#
     token_rec,_ = secure_recv(server_sock,shared_secret)
     token = bytes.fromhex(token_rec["login_token"])

     if token_rec is None:
         raise ValueError("No logintoken received from server")
    
     sign_login_token_start=time.perf_counter()
     signed_Login_Token= cl_alg.sign(cl_sk,token)
     sign_login_token_end=time.perf_counter()
    
     _= secure_send(server_sock,{
       "signature":base64.b64encode
              (signed_Login_Token).decode()},shared_secret)

     login_flag = recv_json(server_sock)
     if login_flag is None:
         raise ValueError("No login_flag received from server")
    
     if not login_flag["login_flag"]:
        raise ValueError("Not verified to login")
    
     print("Login successful and signature verified")

     TLS_handshake_end=time.perf_counter()

     patient_id=user.choose_a_patient()

     _=secure_send(server_sock,{"choosen_patient": patient_id},shared_secret)
    
#---------ABE POFP-----#
     TA_DATA,_ = secure_recv(server_sock,shared_secret)
     if TA_DATA is None:
      raise ValueError("No data received from TA")

     ABE_public_key = bytesToObject(base64.b64decode(TA_DATA["ABE_public_key"]), ABE_group)
     SK_att         = bytesToObject(base64.b64decode(TA_DATA["SK_att"]), ABE_group)
     abe_ct         = bytesToObject(base64.b64decode(TA_DATA["abe_ct"]), ABE_group)
     POFP_Token     = base64.b64decode(TA_DATA["POFP_Token"])
    

     POFP_start=time.perf_counter()
     ABEdec_start = time.perf_counter()
     decrypted_int_key = CP_ABE.decrypt(ABE_public_key, SK_att, abe_ct)
     ABEdec_end = time.perf_counter()
    
    

     cl_derive_AES_KEY_start = time.perf_counter()
     CL_AES_KEY = user.Derive_AES_Key_From_encrypted_int_key(decrypted_int_key, ABE_group)
     cl_derive_AES_KEY_end = time.perf_counter()
    

     ENC_SIG_POFP_TOKEN,enc_time,sign_time=user.Verify_possession_AES_key(username,POFP_Token, CL_AES_KEY)

    
     ENC_DEC_TIME_1=secure_send(server_sock,ENC_SIG_POFP_TOKEN,shared_secret)

#------Decrypt col------#
     encrypted_col_rec,ENC_DEC_TIME_2 = secure_recv(server_sock,shared_secret)
     POFP_end=time.perf_counter()
     if encrypted_col_rec is None:
         raise ValueError("No encrypted_col_rec received from server")
    
     if not encrypted_col_rec["flag"]:
        raise ValueError("POFP not sussessful ")
    
     encrypted_col = base64.b64decode(encrypted_col_rec["encrypted_col"]).decode("utf-8")
     AES_dec_start = time.perf_counter()
     user.Decrypt_Patient_Col_AES(encrypted_col, CL_AES_KEY)
     AES_dec_end = time.perf_counter()
    

     Latency_end = time.perf_counter()

     latency=(Latency_end - Latency_start)* 1000
     cl_Key_Derive=(cl_derive_AES_KEY_end - cl_derive_AES_KEY_start)* 1000
     AES_DEC=(AES_dec_end - AES_dec_start) * 1000
     cl_keygen=(cl_keygen_end - cl_keygen_start) *1000
     signlogintoken= (sign_login_token_end - sign_login_token_start)*1000
     abe_dec =(ABEdec_end - ABEdec_start)*1000
     TLS_handshake=(TLS_handshake_end - TLS_handshake_start)*1000
     POFP_time=(POFP_end - POFP_start)*1000
     verify_chain=(verify_chain_end -verify_chain_start)*1000
     verify_server=(verify_server_end -verify_server_start)*1000
     ENC_DEC_TIME=ENC_DEC_TIME_1 + ENC_DEC_TIME_2 


     CSV_FILE = "client.csv"

     if not os.path.exists(CSV_FILE):
      with open(CSV_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Algorithm",
            "Latency",
            "Client key derive",
            "ABE Dec",
            "EncPOFP",
            "signPOFP",
            "AES Dec",
            "keygen",
            "sign (login token)",
            "TLS_handshake",
            "POFP_time",
            "verify_chain",
            "verify_server",
            "CLIENT_POFP_COMM_EN_DEC_TIME"
        ])
    
     with open(CSV_FILE, "a", newline="") as f:
      writer = csv.writer(f)
      writer.writerow([
        ALGORITHMS[cl_alg],
        f"{latency:.3f}",
        f"{cl_Key_Derive:.3f}",
        f"{abe_dec:.3f}",
        f"{enc_time:.3f}",
        f"{sign_time:.3f}",
        f"{AES_DEC:.3f}",
        f"{cl_keygen:.3f}",
        f"{signlogintoken:.3f}",
        f"{TLS_handshake:.3f}",
        f"{POFP_time:.3f}",
        f"{verify_chain:.3f}",
        f"{verify_server:.3f}",
        f"{ENC_DEC_TIME:.3f}"
    ])

    
    
     print(f"""User Algorithm: {ALGORITHMS[cl_alg]}\n
          Latency for new client: {latency:.3f}\n
          Client key derive: {cl_Key_Derive:.3f}\n
          ABE Decryption: {abe_dec:.3}\n
          AES Decryption: {AES_DEC:.3f}\n
          Client key generation: {cl_keygen:.3f}\n
          Client Signature time (login token): {signlogintoken:.3f}\n
          TLS Handshake time: {TLS_handshake:.3f}\n
          All Proof of Possession time:{POFP_time:.3f}\n
          Verify Certificate chain: {verify_chain:.3f}\n
          Verify server:{verify_server:.3f}\n """)
     iteration= iteration + 1

    except Exception:
     traceback.print_exc()

    finally:
     server_sock.close()
     time.sleep(1)
     print("Connection closed.")