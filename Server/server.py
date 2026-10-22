# Author: Maya Thabet October 22nd 2026
import base64
import json
import os
import sys
import bcrypt
import psycopg2
from pqcrypto.sign import (
    ml_dsa_44, ml_dsa_65, ml_dsa_87,
    sphincs_sha2_128f_simple, sphincs_sha2_192f_simple, sphincs_sha2_256f_simple
)
from charm.toolbox.pairinggroup import PairingGroup, GT
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
from charm.core.engine.util import objectToBytes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from asn1crypto import x509, core, csr, keys, pem

SIG_ALGS_OIDS = { 
    ml_dsa_44 : "2.16.840.1.101.3.4.3.17",
    ml_dsa_65 : "2.16.840.1.101.3.4.3.18",
    ml_dsa_87 :"2.16.840.1.101.3.4.3.19",
    sphincs_sha2_128f_simple:"2.16.840.1.101.3.4.3.21",
    sphincs_sha2_192f_simple:"2.16.840.1.101.3.4.3.23",
    sphincs_sha2_256f_simple:"2.16.840.1.101.3.4.3.25"
}

OID_TO_ALGORITHM = {
    "2.16.840.1.101.3.4.3.17": ml_dsa_44,
    "2.16.840.1.101.3.4.3.18": ml_dsa_65,
    "2.16.840.1.101.3.4.3.19": ml_dsa_87,
    "2.16.840.1.101.3.4.3.21": sphincs_sha2_128f_simple,
    "2.16.840.1.101.3.4.3.23": sphincs_sha2_192f_simple,
    "2.16.840.1.101.3.4.3.25": sphincs_sha2_256f_simple
}
NAME_TO_ALGORITHM = {
    "pqcrypto.sign.ml_dsa_44": ml_dsa_44,
    "pqcrypto.sign.ml_dsa_65": ml_dsa_65,
    "pqcrypto.sign.ml_dsa_87": ml_dsa_87,
    "pqcrypto.sign.sphincs_sha2_128f_simple": sphincs_sha2_128f_simple,
    "pqcrypto.sign.sphincs_sha2_192f_simple": sphincs_sha2_192f_simple,
    "pqcrypto.sign.sphincs_sha2_256f_simple": sphincs_sha2_256f_simple
}

def connection_to_DB(): 
 con = psycopg2.connect(
    host="clinic-db",
    port=5432,
    dbname="clinic",
    user="postgres",
    password="postgres")
 cur = con.cursor()

 return cur,con

def maps_list():
 role_table_map = {
    "Doctor": "doctors",
    "Secretary": "Secretaries",
    "Nurse": "nurses"
 }

 column_map = {
    "Cardiologist": "Cardiology",
    "Orthopedic": "Orthopedics",
    "Any": "personal_info"
 }

 alg_map = {
    "1": ml_dsa_44,
    "2": ml_dsa_65,
    "3": ml_dsa_87,
    "4": sphincs_sha2_128f_simple,
    "5": sphincs_sha2_192f_simple,
    "6": sphincs_sha2_256f_simple,
 }
 return alg_map,column_map,role_table_map

def verify_login(table,username,password):
    cur,con= connection_to_DB()
    cur.execute(
        f"SELECT id,name,username,password_hash,\
              specialty FROM {table} \
              WHERE username = %s;",
        (username,)
    )
    row = cur.fetchone()
    if not row:
        return None, None, None, False

    id,name, username, hash,speciality = row
    stored_hash = bytes(hash)
    return id,name,speciality, verify_password(password, stored_hash)

def verify_password(entered_password,stored_hash):
    if bcrypt.checkpw(entered_password.encode('utf-8'), stored_hash):
        return True 
    else:
        return False

def show_allowed_patients_for_doctor(cur,userid):
    cur.execute("""SELECT p.id, p.name 
        FROM patients p 
        JOIN Appointments app ON p.id = app.patient_id 
        WHERE app.doctor_id = %s; """,(userid,))
    allowed_patients = cur.fetchall()
    if not allowed_patients: 
        ValueError("No patients assigned to you.")  
    return allowed_patients

def show_allowed_patients_for_secretary(cur, sec_id):
    cur.execute("""
        SELECT DISTINCT p.id, p.name
        FROM patients p
        JOIN Appointments app ON p.id = app.patient_id
        JOIN Doctors d ON app.doctor_id = d.id
        WHERE d.secretary_id = %s;
    """, (sec_id,))

    allowed_patients = cur.fetchall()

    if not allowed_patients:
        raise ValueError("No patients available for your assigned doctors.")

    return allowed_patients

def show_allowed_patients_for_nurse(cur, nurse_id):
    cur.execute("""
        SELECT DISTINCT p.id, p.name
        FROM patients p
        JOIN Appointments app ON p.id = app.patient_id
        JOIN Doctors d ON app.doctor_id = d.id
        WHERE d.secretary_id = %s;
    """, (nurse_id,))

    allowed_patients = cur.fetchall()

    if not allowed_patients:
        raise ValueError("No patients available for your assigned doctors.")

    return allowed_patients

def Fetch_Encrypted_data_For_desired_patient(cur,col_name,chosen_patient):

 cur.execute(f"""Select {col_name} from patients 
                        where id =%s; """,(chosen_patient,))
 row = cur.fetchone()
 col=row[0]

  
 return col 

def choose_algorithm(Ben):
    ALGORITHMS = {
    ml_dsa_44: "ml_dsa_44",
    ml_dsa_65: "ml_dsa_65",
    ml_dsa_87: "ml_dsa_87",
    sphincs_sha2_128f_simple: "sphincs_sha2_128f_simple",
    sphincs_sha2_192f_simple: "sphincs_sha2_192f_simple",
    sphincs_sha2_256f_simple: "sphincs_sha2_256f_simple"}
    
    alg=ml_dsa_44
    
    if alg not in SIG_ALGS_OIDS:
        raise ValueError(f"""Maya! \n 
                         Algorithm {alg} not supported by the code\n
                         From  function: choose_algorithm for {Ben}""")
    print(f"{Ben}'s algorithm is {ALGORITHMS[alg]}")
    return alg

def Generate_PQ_Signature_Keys(algorithm,):
    filename = "server_keys.json"

    if os.path.exists(filename):
        os.remove(filename)
        

    pk, sk = algorithm.generate_keypair()

    Keys = {
        "public_key": base64.b64encode(pk).decode("utf-8"),
        "secret_key": base64.b64encode(sk).decode("utf-8"),
        "algorithm": algorithm.__name__
    }

    with open(filename, "w") as f:
        json.dump(Keys, f)

    print(f"Keys for server are generated and saved successfully.")

def Read_Keys():
 filename = "server_keys.json"
 
 if not os.path.exists(filename):
        raise FileNotFoundError(f"file not found: {filename}")

 with open(filename, "r") as f:
     keys = json.load(f)

     pk = base64.b64decode(keys["public_key"])
     sk = base64.b64decode(keys["secret_key"])
     algorithm=keys["algorithm"] 

 return pk,sk,algorithm

def Generate_CSR(algorithm):
    pk,sk,_=Read_Keys()

    if algorithm not in SIG_ALGS_OIDS:
        print("Invalid Algorithm")
        sys.exit(1)

    pub_key_bitstring = core.OctetBitString(pk)

    CSR_info = csr.CertificationRequestInfo({
        'version': 'v1',
        'subject': x509.Name.build({
            'common_name': "Access Control server",
            'title': "ACS"}),
        'subject_pk_info': keys.PublicKeyInfo({
            'algorithm': keys.PublicKeyAlgorithm({
                'algorithm': SIG_ALGS_OIDS[algorithm],
                'parameters': None
            }),
            'public_key': pub_key_bitstring
        })
    })

    # Sign the CSR
    to_be_signed = CSR_info.dump()
    signature = algorithm.sign(secret_key=sk, message=to_be_signed)

    CSR = csr.CertificationRequest({
        'certification_request_info': CSR_info,
        'signature_algorithm': x509.SignedDigestAlgorithm({
            'algorithm': SIG_ALGS_OIDS[algorithm],
            'parameters': None
        }),
        'signature': signature
    })

    # Convert to PEM
    CSR_PEM = pem.armor(
        'CERTIFICATE REQUEST',
        CSR.dump()
    ).decode('utf-8')

    print("server CSR generated")

    return CSR_PEM


def verify_cl_crt(cl_crt,ICA_crt,CA_crt):
    flag=False

    ICA_PAYLOAD=cl_crt["tbs_certificate"].dump()
    ICA_PK=ICA_crt["tbs_certificate"]["subject_public_key_info"]["public_key"].native   
    ICA_Signature_algorithm_oid=cl_crt["signature_algorithm"]["algorithm"].native
    
    ICA_Signature_algorithm=OID_TO_ALGORITHM[ICA_Signature_algorithm_oid]
    
    ICA_Signature=cl_crt["signature_value"].native
    ica_flag=ICA_Signature_algorithm.verify(ICA_PK,ICA_PAYLOAD,ICA_Signature)
    
    CA_PK=CA_crt["tbs_certificate"]["subject_public_key_info"]['public_key'].native
    
    CA_PAYLOAD=ICA_crt["tbs_certificate"].dump()

    CA_Signature_algorithm_oid=ICA_crt["signature_algorithm"]["algorithm"].native
    
    CA_Signature_algorithm=OID_TO_ALGORITHM[CA_Signature_algorithm_oid]
    
    CA_Signature=ICA_crt["signature_value"].native
    CA_flag=CA_Signature_algorithm.verify(CA_PK,CA_PAYLOAD,CA_Signature)
    
    if CA_flag and ica_flag:
        flag=True
    
    return flag
