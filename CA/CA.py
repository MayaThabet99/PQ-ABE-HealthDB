# Author: Maya Thabet October 22nd 2026

import base64
import datetime
import json
import os
import secrets
from asn1crypto import x509, core, csr, keys, pem
import bcrypt
from pqcrypto.sign import (
    ml_dsa_44, ml_dsa_65, ml_dsa_87,
    sphincs_sha2_128f_simple, sphincs_sha2_192f_simple, sphincs_sha2_256f_simple
)

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

def Extract_data_from_ICA_CSR(csr_data):

    if isinstance(csr_data, str):
       csr_data_bytes = csr_data.encode("utf-8")
    elif isinstance(csr_data, (bytes, bytearray, memoryview)):
         csr_data_bytes = bytes(csr_data)
    else:
        raise TypeError( f"""P_ICA_CSR data must be str or bytes-like, got {type(csr_data)}\n
                        From function: Extract_data_from_P_ICA_CSR""")


    if pem.detect(csr_data_bytes):
        type_name, headers, der_bytes = pem.unarmor(csr_data_bytes)
        request = csr.CertificationRequest.load(der_bytes)
    else:
        raise TypeError("P_ICA_CSR is not a valid PEM.")

    info = request['certification_request_info']

    CSR_INFO = info.dump()
    
    subject = info['subject'] 
    
    public_key_info_object = info['subject_pk_info']
    
    oid = info['subject_pk_info']['algorithm']['algorithm'].native
    public_key_bytes = info['subject_pk_info']['public_key'].native
    signature = request['signature'].native

    if oid not in OID_TO_ALGORITHM:
        raise ValueError(f"algorithm OID not supported by the code\nFrom Function: Extract_data_from_P_ICA_CSR")

    CSR_algo_module = OID_TO_ALGORITHM[oid]

    return CSR_algo_module, CSR_INFO, subject, oid, public_key_bytes, signature, public_key_info_object

def Generate_PQ_Signature_Keys(CA_algorithm):
    filename = "CA_keys.json"

    if os.path.exists(filename):
        os.remove(filename)

    pk, sk = CA_algorithm.generate_keypair()

    Keys = {
        "public_key": base64.b64encode(pk).decode("utf-8"),
        "secret_key": base64.b64encode(sk).decode("utf-8"),
        "algorithm": CA_algorithm.__name__
    }

    with open(filename, "w") as f:
        json.dump(Keys, f)

    print(f"Keys for CA generated and saved successfully.")

def Read_Keys():
 filename = "CA_keys.json"

 if not os.path.exists(filename):
        raise FileNotFoundError(f"file not found: {filename}")

 with open(filename, "r") as f:
     keys = json.load(f)

     pk = base64.b64decode(keys["public_key"])
     sk = base64.b64decode(keys["secret_key"])
    
     alg_name = keys["algorithm"] 
     if alg_name not in NAME_TO_ALGORITHM:
        raise ValueError(f"Maya!\nUnknown algorithm name in keys: {alg_name}")
        
     algorithm = NAME_TO_ALGORITHM[alg_name]

     return pk, sk, algorithm
 
def CA_Issue_Self_signed_crt(CA_algorithm):
  CA_PK,CA_SK,_=Read_Keys()
  filename = "CA_Self_signed_Cert.pem"

  if os.path.exists(filename):
        os.remove(filename)
 
  name = x509.Name.build({
        'organization_name': 'CA',
        'common_name': 'clinic Root CA'
    })
  
  extensions = [
        x509.Extension({
            'extn_id': 'basic_constraints',
            'critical': True,
            'extn_value': x509.BasicConstraints({
                'ca': True,
                'path_len_constraint': None
            })
        }),
        x509.Extension({
            'extn_id': 'key_usage',
            'critical': True,
            'extn_value': x509.KeyUsage({
                'key_cert_sign'
            })
        }),
    ]
  
  now = datetime.datetime.now(datetime.timezone.utc)
  end = now + datetime.timedelta(days=365)

  CA_signature_algo = x509.SignedDigestAlgorithm({
        'algorithm': SIG_ALGS_OIDS[CA_algorithm],
        'parameters': None
    })
  spki = keys.PublicKeyInfo({
        'algorithm': keys.PublicKeyAlgorithm({
            'algorithm': SIG_ALGS_OIDS[CA_algorithm],
            'parameters': None
        }),
        'public_key': core.OctetBitString(CA_PK)
    })

  to_be_signed_cert = x509.TbsCertificate({
        'version': 'v3',
        'serial_number': secrets.randbits(128),
        'signature': CA_signature_algo,
        'issuer': name,
        'validity': x509.Validity({
            'not_before': x509.Time({'utc_time': now}),
            'not_after':  x509.Time({'utc_time': end})
        }),
        'subject': name,  
        'subject_public_key_info': spki, 
        'extensions': extensions
    })
  
  to_be_signed_bytes = to_be_signed_cert.dump()
  print(f"Signing self signed Certificate with CA Key ({CA_algorithm.__name__})...")

  if isinstance(CA_SK, tuple):
      CA_SK = CA_SK[0]
  if isinstance(CA_SK, memoryview):
      CA_SK = bytes(CA_SK)
  elif not isinstance(CA_SK, bytes):
       raise TypeError(f"CA_SK must be bytes, got {type(CA_SK)}")

  CA_signature = CA_algorithm.sign(secret_key=CA_SK, message=to_be_signed_bytes)

  cert = x509.Certificate({
        'tbs_certificate': to_be_signed_cert,
        'signature_algorithm': CA_signature_algo,
        'signature_value': CA_signature
    })


  cert_pem = pem.armor('CERTIFICATE', cert.dump()).decode('utf-8')

       
  with open(filename, "w") as f:
        f.write(cert_pem)

  print(f"Self-signed CA certificate saved as {filename}.")

  return cert_pem

def CA_Issue_ICA_CRT(CSR):
    CA_PK,CA_SK,CA_algorithm=Read_Keys()
    filename = "ICA_Cert.pem"
    with open("CA_Self_signed_Cert.pem", "rb") as f:
        cert_data = f.read()

    if pem.detect(cert_data):
     _, _, der_bytes = pem.unarmor(cert_data)
    else:
     der_bytes = cert_data

    root_cert = x509.Certificate.load(der_bytes)

    if os.path.exists(filename):
        os.remove(filename)
    
    ICA_alg, ICA_CSR_INFO, subject, oid, ICA_public_key_bytes, ICA_signature, ICA_pub_key_object = Extract_data_from_ICA_CSR(CSR)

    if not ICA_alg.verify(ICA_public_key_bytes,ICA_CSR_INFO,ICA_signature):
        raise ValueError("CSR Signature not valid can not generate a certificate\nFrom function:CA_Issue_ICA_CRT")
    
    now = datetime.datetime.now(datetime.timezone.utc)
    end = now + datetime.timedelta(days=365)

    issuer = root_cert['tbs_certificate']['subject']
    
    CA_signature_algo = x509.SignedDigestAlgorithm({
        'algorithm': SIG_ALGS_OIDS[CA_algorithm],
        'parameters': None
    })

    to_be_signed_cert = x509.TbsCertificate({
        'version': 'v3',
        'serial_number': secrets.randbits(128),
        'signature': CA_signature_algo,
        'issuer': issuer,
        'validity': x509.Validity({
            'not_before': x509.Time({'utc_time': now}),
            'not_after':  x509.Time({'utc_time': end})
        }),
        'subject': subject,  
        'subject_public_key_info': ICA_pub_key_object, 
        'extensions': [
            x509.Extension({
                'extn_id': 'basic_constraints',
                'critical': True,
                'extn_value': x509.BasicConstraints({
                    'ca': True, 
                    'path_len_constraint': 0 
                })
            }),
            x509.Extension({
                'extn_id': 'key_usage',
                'critical': True,
                'extn_value': x509.KeyUsage({'key_cert_sign'})
            })
        ]
    })

    to_be_signed_bytes=to_be_signed_cert.dump()

    if isinstance(CA_SK, tuple):
      CA_SK = CA_SK[0]
    if isinstance(CA_SK, memoryview):
      CA_SK = bytes(CA_SK)
    elif not isinstance(CA_SK, bytes):
       raise TypeError(f"CA_SK must be bytes, got {type(CA_SK)}")

    CA_signature = CA_algorithm.sign(
        secret_key=CA_SK, message=to_be_signed_bytes)


    cert = x509.Certificate({
        'tbs_certificate': to_be_signed_cert,
        'signature_algorithm': CA_signature_algo,
        'signature_value': CA_signature
    })



    cert_pem = pem.armor('CERTIFICATE', cert.dump()).decode('utf-8')

       
    with open(filename, "w") as f:
        f.write(cert_pem)

    print("cert generated and saved successfully.")

    return cert_pem
