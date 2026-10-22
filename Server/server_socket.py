# Author: Maya Thabet October 22nd 2026
import base64
import csv
import json
import os
import time
import server
import socket
import struct
import psycopg2
from Crypto.Cipher import AES
from asn1crypto import x509, pem
import traceback
from pqcrypto.kem import ml_kem_512
import pickle
import struct
from Crypto.Random import get_random_bytes
from pqcrypto.sign import (
    ml_dsa_44, ml_dsa_65, ml_dsa_87,
    sphincs_sha2_128f_simple, sphincs_sha2_192f_simple, sphincs_sha2_256f_simple)
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

NAME_TO_ALGORITHM = {
    "ml_dsa_44": ml_dsa_44,
    "ml_dsa_65": ml_dsa_65,
    "ml_dsa_87": ml_dsa_87,
    "sphincs_sha2_128f_simple": sphincs_sha2_128f_simple,
    "sphincs_sha2_192f_simple": sphincs_sha2_192f_simple,
    "sphincs_sha2_256f_simple": sphincs_sha2_256f_simple,
}

OID_TO_ALGORITHM = {
    "2.16.840.1.101.3.4.3.17": ml_dsa_44,
    "2.16.840.1.101.3.4.3.18": ml_dsa_65,
    "2.16.840.1.101.3.4.3.19": ml_dsa_87,
    "2.16.840.1.101.3.4.3.21": sphincs_sha2_128f_simple,
    "2.16.840.1.101.3.4.3.23": sphincs_sha2_192f_simple,
    "2.16.840.1.101.3.4.3.25": sphincs_sha2_256f_simple
}
print("Starting server...")

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

server_socket.bind(("0.0.0.0", 8000))

server_socket.listen()

print("Server listening on port 8000...",flush=True)


try:
    db = psycopg2.connect(
        host="clinic-db",
        dbname="clinic",
        user="postgres",
        password="postgres"
    )
    cur = db.cursor()
    print("Database connected",flush=True)

except Exception as e:
    print("Database connection failed:",flush=True)
    print(e)




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
#-----------------ICA Connection------------------#
    ica_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ica_sock.connect(("ica", 5001))
    print("Connected to ICA!")

#-----------------Server-CRT-----------------#
    server_alg=server.choose_algorithm("server")
    server_keyGen_start = time.perf_counter()
    server.Generate_PQ_Signature_Keys(server_alg)
    server_keyGen_end = time.perf_counter()


    server_csr=server.Generate_CSR(server_alg)

    send_json(ica_sock,{
            "Info": "server csr",
            "CSR": server_csr
        })

    crt_rec=recv_json(ica_sock)
    if crt_rec is None:
       raise ValueError("No crt received fromo ICA")
    
    CRT=crt_rec["crt"]
    ICA=crt_rec["ICA_CRT"]
    CA=crt_rec["CA_CRT"]

    print("Waiting for client connection...",flush=True)

    conn, addr = server_socket.accept()

    print(f"Connected by {addr}",flush=True)

    try:
        hello = recv_json(conn)

        if hello is None:
         raise ValueError("No hello received from client")
        
        KEM_PK, KEM_SK = ml_kem_512.generate_keypair()
        pk,sk,_=server.Read_Keys()

        server_sign_start=time.perf_counter()  
        kem_signature = server_alg.sign(sk, KEM_PK)
        server_sign_end=time.perf_counter()  

        
        send_json(conn, {
           "certificate": CRT,
           "kem_public_key": KEM_PK.hex(),
           "kem_signature": base64.b64encode
              (kem_signature).decode()})

        clcrtreq = recv_json(conn)

        cl_CRT=clcrtreq["certificate"]

        if isinstance(cl_CRT, str):
              cl_CRT = cl_CRT.encode("utf-8")
        if pem.detect(cl_CRT):
            _, _, cl_der_bytes = pem.unarmor(cl_CRT)
        else:
            cl_der_bytes = cl_CRT
        
        cl_cert = x509.Certificate.load(cl_der_bytes)
        
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
        crt_flag=server.verify_cl_crt(cl_cert,ICA_cert,CA_cert)
    

        if not crt_flag:
           raise ValueError("cl crt is not verified")
           

#---------cl_LOGIN---------#
        KEM_Ciphertext=recv_json(conn)

        print("DEBUG KEM_Ciphertext:", KEM_Ciphertext, flush=True)
        print("DEBUG TYPE:", type(KEM_Ciphertext), flush=True)

        if KEM_Ciphertext is None:
         raise ValueError("No KEM ciphertext received from client")

        if "KEM_Ciphertext" not in KEM_Ciphertext:
         raise ValueError(f"Expected KEM_Ciphertext, received keys: {list(KEM_Ciphertext.keys())}")   

        ciphertext = bytes.fromhex(KEM_Ciphertext["KEM_Ciphertext"])
        shared_secret =ml_kem_512.decrypt(
           KEM_SK,ciphertext)
        Loginreq,_ = secure_recv(conn,shared_secret)

        if Loginreq is None:
         raise ValueError("No login data received from client")
        
        alg_map,column_map,role_table_map=server.maps_list()

        
        cl_id, cl_name, cl_speciality, login_flag \
         = server.verify_login(
                role_table_map[Loginreq["role"]],
                Loginreq["username"],
                Loginreq["password"])

        if login_flag:
            print(f"Password is correct",flush=True)
        else:
                raise ValueError("Password incorrect")
       
# #--------------------Login token--------------#
        logintoken= os.urandom(32)

        _=secure_send(conn,{
     "Info": "login token",
     "login_token": logintoken.hex()},shared_secret)

        signed_Login_Token_req,_ = secure_recv(conn,shared_secret) 

        if signed_Login_Token_req is None:
         raise ValueError("No signed_Login_Token received from client")
        
        CL_signature=base64.b64decode(
        signed_Login_Token_req["signature"].encode("utf-8"))

        cl_pk=cl_cert["tbs_certificate"]["subject_public_key_info"]["public_key"].native
            
        cl_Signature_algorithm_oid=cl_cert["tbs_certificate"]["subject_public_key_info"]["algorithm"]["algorithm"].native
        cl_alg=OID_TO_ALGORITHM[cl_Signature_algorithm_oid]
            
        verify_server_start=time.perf_counter()
         
        verify_cl_start = time.perf_counter() 
        login_access=cl_alg.verify(
        cl_pk,logintoken,CL_signature)
        verify_cl_end = time.perf_counter() 
 
        send_json(conn,{
    "login_flag":login_access
 })

#----------Show patients------------#
        match Loginreq["role"]:
         case"Doctor":
            allowed_patients=\
            server.show_allowed_patients_for_doctor(cur,cl_id)
         case"Secretary":
            allowed_patients=\
            server.show_allowed_patients_for_secretary(cur,cl_id)
         case"Nurse":
            allowed_patients=\
            server.show_allowed_patients_for_nurse(cur,cl_id)
         case _:
            raise ValueError("Maya! role is wrong")
           
        chossen_patient_rec,_ = secure_recv(conn,shared_secret)

        if chossen_patient_rec is None:
         raise ValueError("No chossen_patient_rec received from client")
        
#-----------Send ABE data to TA------#
        
        ta_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ta_sock.connect(("ta", 5002))
        print("Connected to TA!")     

        allowed_ids = {pid for pid, _ in allowed_patients} 
        Access = "True"
   
        if chossen_patient_rec["choosen_patient"] not in allowed_ids: 
          Access = "False"
        
        start=time.perf_counter()
        send_json(ta_sock,{"Access_flag":Access,
                           "col":column_map[cl_speciality],
                           "speciality": cl_speciality,
                           "role":Loginreq["role"],
                           "Start_time": start,
                           "Patient_id":chossen_patient_rec["choosen_patient"]})
        
        
        ABE_CL_DATA = recv_json(ta_sock)
        start=ABE_CL_DATA["Start_time"]
        end=time.perf_counter()
        ABE_cl_data_Connection_TIME=(end-start)*1000

        if ABE_CL_DATA is None:
         raise ValueError("No ABE_CL_DATA received from TA")
        
        _=secure_send(conn,ABE_CL_DATA,shared_secret)
#-----------POFP---------------#
        POFP_DATA,ENC_DEC_TIME_1 = secure_recv(conn,shared_secret)

        if POFP_DATA is None:
         raise ValueError("No POFP_DATA received from client")
        
        send_json(ta_sock,POFP_DATA)

        
        POFP_SIG=recv_json(ta_sock)
        if POFP_SIG is None:
         raise ValueError("No POFP_SIG received from TA")
        
        POFP_ENC_FLAG=POFP_SIG["POFP_ENC_FLAG"]

        POFP_MSSG_SIG_bytes=base64.b64decode(POFP_SIG["POFP_MSSG_SIG"])
        
        POFP_SIG_bytes=base64.b64decode(POFP_SIG["POFP_SIG"])
        
        POFP_VERIFY_CLIENT_START=time.perf_counter()
        POFP_SIG_FLAG=cl_alg.verify(cl_pk,POFP_MSSG_SIG_bytes,POFP_SIG_bytes) 
        POFP_VERIFY_CLIENT_END=time.perf_counter()
        

        if POFP_SIG_FLAG &  POFP_ENC_FLAG:
           print("AES key possession and identity is verified.")
           ENC_DEC_TIME_2=secure_send(conn,{"encrypted_col":POFP_SIG["encrypted_data"],
                           "flag": True},shared_secret)
        else:
           ENC_DEC_TIME_2=secure_send(conn,{"encrypted_col":False,
                           "flag": False},shared_secret)
        
        keygen_time=(server_keyGen_end - server_keyGen_start)*1000
        sign_time=(server_sign_end - server_sign_start)*1000
        verify_client=(verify_cl_end - verify_cl_start)*1000
        POFP_verify=(POFP_VERIFY_CLIENT_END - POFP_VERIFY_CLIENT_START)*1000
        ENC_DEC_TIME=ENC_DEC_TIME_1 + ENC_DEC_TIME_2
        
        CSV_FILE = "s.csv"
        if not os.path.exists(CSV_FILE):
         with open(CSV_FILE, "w", newline="") as f:
          writer = csv.writer(f)
          writer.writerow([
    "keygen_time",
    "sign_time",
    "verify_client",
    "Verify_POFP",
    "SERVER_POFP_COMM_EN_DEC_TIME",
    "ABE_cl_data_Connection_TIME"])
 
        with open(CSV_FILE, "a", newline="") as f:
         writer = csv.writer(f)
         writer.writerow([   
    f"{keygen_time:.3f}",
    f"{sign_time:.3f}",
    f"{verify_client:.3f}",
    f"{POFP_verify:.3f}",
    f"{ENC_DEC_TIME:.3f}",
    f"{ABE_cl_data_Connection_TIME:.3f}"])


    except Exception as e:
        print("Error handling client:",flush=True)
        traceback.print_exc()

    finally:
        conn.close()
        print("Connection closed.",flush=True)

    