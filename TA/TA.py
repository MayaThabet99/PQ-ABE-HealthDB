# Author: Maya Thabet October 22nd 2026
import ast
import binascii
import json
import os
import base64
import psycopg2
import sys
import time
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from charm.toolbox.pairinggroup import PairingGroup,GT
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07

def create_token(): return os.urandom(32)

def gen_SK_att(Access,speciality,role,session_id,public_key,master_key,CP_ABE):
    access = Access.strip().upper()
    spec = speciality.strip().upper()
    attributes = [
            role.upper(),
            spec,
            access,
            session_id
        ]
    att_size = sys.getsizeof(attributes)

    SK_KEYGEN_START = time.perf_counter()
    SK_att = CP_ABE.keygen(public_key, master_key, attributes)
    SK_KEYGEN_END = time.perf_counter()
    SK_KEYGEN = (SK_KEYGEN_END - SK_KEYGEN_START)*1000
    return SK_att,att_size,SK_KEYGEN

def serialize_dict(d,group):
    return {k: group.serialize(v).hex() for k, v in d.items()}

def Write_ABE_SETUP():
    START = time.perf_counter()

    group = PairingGroup('MNT224')
    CP_ABE = CPabe_BSW07(group)

    public_key, master_key = CP_ABE.setup()
    END = time.perf_counter()

    data = {
    "curve": "MNT224",
    "public_key": serialize_dict(public_key,group),
    "master_key": serialize_dict(master_key,group)}

    if os.path.exists("abe_keys.json"):  
     os.remove("abe_keys.json") 
     print("Deleted old ABE , creating a new")

    with open("abe_keys.json", "w") as f:
      json.dump(data, f)
      
    return (END - START)*1000

def deserialize_dict(d,group):
    return {k: group.deserialize(bytes.fromhex(v)) for k, v in d.items()}

def Read_ABE_SETUP():
    with open("abe_keys.json", "r") as f:
     data = json.load(f)

    group = PairingGroup(data["curve"])
    CP_ABE = CPabe_BSW07(group)

    public_key = deserialize_dict(data["public_key"],group)
    master_key = deserialize_dict(data["master_key"],group)
    return group,CP_ABE,public_key,master_key

def normalize_aes_key(value):


    if isinstance(value, memoryview):
        return bytes(value)

    if isinstance(value, bytes):
        return value

    if isinstance(value, str):
        s = value.strip()

        if s.startswith("b'") or s.startswith('b"'):
            try:
                real_bytes = ast.literal_eval(s)
                if isinstance(real_bytes, bytes):
                    return real_bytes
            except Exception:
                pass

        try:
            return base64.b64decode(s, validate=True)
        except Exception:
            pass

        try:
            return binascii.unhexlify(s)
        except Exception:
            pass

        return s.encode("latin1")

    raise TypeError(f"Unsupported AES key type: {type(value)}")

def derive_aes_key(column_name):

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,                    
        salt=b"optional-salt",
        info=b"session encryption key"
    )

    int_key = get_intermediate_key(column_name)
    
    if int_key is not None:
        if isinstance(int_key, str):
            ik_bytes = bytes.fromhex(int_key[2:])
        else:
            ik_bytes = int_key
            
        aes_key = hkdf.derive(ik_bytes)
        AES_key = normalize_aes_key(aes_key)
        print(f"AES key with TA:{AES_key}")
        return AES_key
        
    raise ValueError("Maya! Int_key is None")

def decrypt_verification(aes_key, data, expected_challenge):

    iv = base64.b64decode(data["iv"])
    tag = base64.b64decode(data["tag"])
    ciphertext = base64.b64decode(data["ciphertext"])
    signature = data["signature"]
    
    payload_bytes = iv + tag + ciphertext
    payload=base64.b64encode(payload_bytes).decode("utf-8")

    print("AES:", aes_key.hex())
    print("IV :", iv.hex())
    print("TAG:", tag.hex())
    print("CT :", ciphertext.hex())

    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
    POFP_DEC_TA_START=time.perf_counter()
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    POFP_DEC_TA_END=time.perf_counter()

    POFP_DEC=(POFP_DEC_TA_END - POFP_DEC_TA_START)*1000

    if plaintext != expected_challenge:
        print(" Challenge mismatch (wrong AES key).")
        return False,signature,payload,POFP_DEC

    return True,signature,payload,POFP_DEC


def connection_to_DB(): 
 con = psycopg2.connect(
    host="clinic-db",
    port=5432,
    dbname="clinic",
    user="postgres",
    password="postgres")
 cur = con.cursor()

 return cur,con


def get_perm_aes_key(column_name):
    with open("col_keys.json") as f:
        data = json.load(f)

    for item in data:
        if item["col_name"] == column_name:
            raw_key = item["permanent_aes_key"]

            if isinstance(raw_key, str) and raw_key.startswith("0x"):
                old_aes_key = bytes.fromhex(raw_key[2:])

            else:
                old_aes_key = normalize_aes_key(raw_key)

            print("Old AES key type:", type(old_aes_key))
            print("Old AES key length:", len(old_aes_key))

            if len(old_aes_key) not in (16, 24, 32):
                raise ValueError(
                    f"Invalid AES key length: {len(old_aes_key)} bytes"
                )

            return old_aes_key

    raise ValueError(f"No permanent AES key found for column: {column_name}")

def Encrypt_intermediate_key_With_ABE(group, col_name, CP_ABE, public_key, session_id):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,                    
        salt=b"optional-salt",
        info=b"session encryption key"
    )
    
    intermediate_key = group.random(GT)
    ik_bytes = group.serialize(intermediate_key)

    aes_key = hkdf.derive(ik_bytes)

    policy_gen_start=time.perf_counter()
    if col_name == "Cardiology":
        policy = f'((DOCTOR OR NURSE) AND CARDIOLOGIST AND TRUE AND {session_id})'
    elif col_name == "Orthopedics":
        policy = f'((DOCTOR OR NURSE) AND ORTHOPEDIC AND TRUE AND {session_id})'
    else:
        policy = f'(SECRETARY AND ANY AND TRUE AND {session_id})'
    policy_gen_end=time.perf_counter()
    
    ABE_ENC_START=time.perf_counter()
    abe_ct = CP_ABE.encrypt(public_key, intermediate_key, policy)
    ABE_ENC_end=time.perf_counter()

    ABE_ENC_TIME=(ABE_ENC_end - ABE_ENC_START)*1000
    policy_gen=(policy_gen_end - policy_gen_start)*1000


    print("Policy:", policy)

    return abe_ct,aes_key,ABE_ENC_TIME,policy_gen

def re_encryption(cur, col_name, new_aes_key, id):
    cur.execute(f"SELECT {col_name} FROM patients WHERE id = %s;", (id,))
    row = cur.fetchone()
    col=row[0]

    old_aes_key = get_perm_aes_key(col_name)

    print("Old AES key type:", type(old_aes_key))
    print("Old AES key length:", len(old_aes_key))
    print("Old AES key:", old_aes_key.hex())

    if len(old_aes_key) not in (16, 24, 32):
     raise ValueError(
        f"Invalid old AES key length: {len(old_aes_key)} bytes") 

    if isinstance(col, tuple):
        col = col[0]

    if isinstance(col, dict):
        data = col
    elif isinstance(col, (str, bytes, bytearray)):
        data = json.loads(col)
    else:
        print(f"Unexpected data type: {type(col)}")
        return None

    ciphertext = base64.b64decode(data["EncryptedData"])
    iv = base64.b64decode(data["IV"])
    tag = base64.b64decode(data["Tag"])

    new_iv = get_random_bytes(12)

    cipher = AES.new(old_aes_key, AES.MODE_GCM, nonce=iv)
    new_cipher = AES.new(new_aes_key, AES.MODE_GCM, nonce=new_iv)

    plaintext_bytes = cipher.decrypt_and_verify(ciphertext, tag)

    ciphertext, tag = new_cipher.encrypt_and_digest(plaintext_bytes)

    encrypted_data = json.dumps({
            "EncryptedData": base64.b64encode(ciphertext).decode(),
            "IV": base64.b64encode(new_iv).decode(),
            "Tag": base64.b64encode(tag).decode()
        })

    print(f"Re-encryption completed successfully.")

    return encrypted_data
