# Author: Maya Thabet October 22nd 2026
import ast
import base64
import binascii
import json
import os
import sys
import time
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from pqcrypto.sign import (
    ml_dsa_44, ml_dsa_65, ml_dsa_87,
    sphincs_sha2_128f_simple, sphincs_sha2_192f_simple, sphincs_sha2_256f_simple,
    sphincs_sha2_128s_simple, sphincs_sha2_192s_simple, sphincs_sha2_256s_simple
)
from asn1crypto import x509, core, csr, keys, pem

SIG_ALGS_OIDS = { 
    ml_dsa_44 : "2.16.840.1.101.3.4.3.17",
    ml_dsa_65 : "2.16.840.1.101.3.4.3.18",
    ml_dsa_87 :"2.16.840.1.101.3.4.3.19",
    sphincs_sha2_128f_simple:"2.16.840.1.101.3.4.3.21",
    sphincs_sha2_192f_simple:"2.16.840.1.101.3.4.3.23",
    sphincs_sha2_256f_simple:"2.16.840.1.101.3.4.3.25",
    sphincs_sha2_128s_simple:"2.16.840.1.101.3.4.3.20",
    sphincs_sha2_192s_simple:"2.16.840.1.101.3.4.3.22",
    sphincs_sha2_256s_simple:"2.16.840.1.101.3.4.3.24"
}

OID_TO_ALGORITHM = {
    "2.16.840.1.101.3.4.3.17": ml_dsa_44,
    "2.16.840.1.101.3.4.3.18": ml_dsa_65,
    "2.16.840.1.101.3.4.3.19": ml_dsa_87,
    "2.16.840.1.101.3.4.3.21": sphincs_sha2_128f_simple,
    "2.16.840.1.101.3.4.3.23": sphincs_sha2_192f_simple,
    "2.16.840.1.101.3.4.3.25": sphincs_sha2_256f_simple,
    "2.16.840.1.101.3.4.3.20": sphincs_sha2_128s_simple,
    "2.16.840.1.101.3.4.3.22": sphincs_sha2_192s_simple,
    "2.16.840.1.101.3.4.3.24": sphincs_sha2_256s_simple,
}
 
NAME_TO_ALGORITHM = {
    "pqcrypto.sign.ml_dsa_44": ml_dsa_44,
    "pqcrypto.sign.ml_dsa_65": ml_dsa_65,
    "pqcrypto.sign.ml_dsa_87": ml_dsa_87,
    "pqcrypto.sign.sphincs_sha2_128f_simple": sphincs_sha2_128f_simple,
    "pqcrypto.sign.sphincs_sha2_192f_simple": sphincs_sha2_192f_simple,
    "pqcrypto.sign.sphincs_sha2_256f_simple": sphincs_sha2_256f_simple
}

def Derive_AES_Key_From_encrypted_int_key(decrypted_int_key,group):
    aes_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=b"optional-salt",
    info=b"session encryption key").derive(group.serialize(decrypted_int_key))

    print(f"AES key with CL: {aes_key}")
    return aes_key

def Verify_possession_AES_key(user_name,challenge_bytes, aes_key):
    """
    Proves possession of the AES key AND the signing private key.
    """
    _,sk,sig_alg=Read_Keys(user_name)
    iv = get_random_bytes(12)
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
    start=time.perf_counter()
    ciphertext, tag = cipher.encrypt_and_digest(challenge_bytes)
    end=time.perf_counter()
    enc_time=(end-start)*1000

    payload = iv + tag + ciphertext
    print(f"Signed POFP size: {payload.__sizeof__()} bytes")


    start=time.perf_counter()
    signature = sig_alg.sign(
        secret_key=sk,
        message=payload
    )
    end=time.perf_counter()
    sign_time=(end-start)*1000



    signed_data = {
        "iv": base64.b64encode(iv).decode("utf-8"),
        "tag": base64.b64encode(tag).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
        "signature": base64.b64encode(signature).decode("utf-8")
    }

    return signed_data,enc_time,sign_time

def Decrypt_Patient_Col_AES(encrypted_col, AES_KEY):
    if isinstance(encrypted_col, tuple):
        encrypted_col = encrypted_col[0]

    if isinstance(encrypted_col, dict):
        data = encrypted_col
    elif isinstance(encrypted_col, (str, bytes, bytearray)):
        data = json.loads(encrypted_col)
    else:
        print(f"Unexpected data type: {type(encrypted_col)}")
        return None

    ciphertext = base64.b64decode(data["EncryptedData"])
    iv = base64.b64decode(data["IV"])
    tag = base64.b64decode(data["Tag"])
    cipher = AES.new(AES_KEY, AES.MODE_GCM, nonce=iv)

    plaintext_bytes = cipher.decrypt_and_verify(ciphertext, tag)
    plaintext = json.loads(plaintext_bytes.decode("utf-8"))
    print(plaintext)

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

def ABE_ONLY_TEST_Verify_possession(challenge_bytes,CP_ABE,public_key,user_sk,abe_ct,group):
    
    decrypted_key = CP_ABE.decrypt(public_key, user_sk, abe_ct)

    hkdf = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=b"optional-salt",
    info=b"session encryption key"
)

    aes_key = hkdf.derive(group.serialize(decrypted_key))

    print(f"AES key with Client: {aes_key}")
    iv = get_random_bytes(12)
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(challenge_bytes)

    enc_data = {
        "iv": base64.b64encode(iv).decode("utf-8"),
        "tag": base64.b64encode(tag).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8")
    }
    return enc_data,aes_key

def choose_a_patient():
    try: 
        chosen_patient = 1
    except:
        ValueError("Invalid patient ID (not an integer).") 
        
    return chosen_patient

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
        raise ValueError(f"""Algorithm {alg} not supported by the code\n
                         From  function: choose_algorithm for {Ben}""")
    print(f"{Ben}'s algorithm is {ALGORITHMS[alg]}")
    return alg

def Generate_PQ_Signature_Keys(algorithm,user_name):
    filename = f"{user_name}_keys.json"

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

    print(f"Keys for {user_name} generated and saved successfully.")

def Read_Keys(user_name):
 filename = f"{user_name}_keys.json"

 if not os.path.exists(filename):
        raise FileNotFoundError(f"file not found: {filename}")

 with open(filename, "r") as f:
     keys = json.load(f)

     pk = base64.b64decode(keys["public_key"])
     sk = base64.b64decode(keys["secret_key"])
     algorithm=keys["algorithm"] 

 return pk,sk,NAME_TO_ALGORITHM[algorithm]

def verify_Server_crt(server_crt,ICA_crt,CA_crt):
    flag=False

    ICA_PAYLOAD=server_crt["tbs_certificate"].dump()
    ICA_PK=ICA_crt["tbs_certificate"]["subject_public_key_info"]["public_key"].native   
    ICA_Signature_algorithm_oid=server_crt["signature_algorithm"]["algorithm"].native
    
    ICA_Signature_algorithm=OID_TO_ALGORITHM[ICA_Signature_algorithm_oid]
    
    ICA_Signature=server_crt["signature_value"].native
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

    

def Generate_CSR(algorithm,cl_name):
    pk,sk,_=Read_Keys(cl_name)

    if algorithm not in SIG_ALGS_OIDS:
        print("Invalid Algorithm")
        sys.exit(1)

    pub_key_bitstring = core.OctetBitString(pk)

    CSR_info = csr.CertificationRequestInfo({
        'version': 'v1',
        'subject': x509.Name.build({
            'common_name': cl_name}),
        'subject_pk_info': keys.PublicKeyInfo({
            'algorithm': keys.PublicKeyAlgorithm({
                'algorithm': SIG_ALGS_OIDS[algorithm],
                'parameters': None
            }),
            'public_key': pub_key_bitstring
        })
    })

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

    CSR_PEM = pem.armor(
        'CERTIFICATE REQUEST',
        CSR.dump()
    ).decode('utf-8')

    print("server CSR generated")

    return CSR_PEM