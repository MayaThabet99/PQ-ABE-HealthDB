# Author: Maya Thabet October 22nd 2026
import base64
import datetime
import json
import os
import secrets
import sys
from asn1crypto import x509, core, csr, keys, pem
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
        raise ValueError(f"""Maya! \n 
                         Algorithm {alg} not supported by the code\n
                         From  function: choose_algorithm for {Ben}""")
    print(f"{Ben}'s algorithm is {ALGORITHMS[alg]}")
    return alg

def Generate_PQ_Signature_Keys(algorithm):
    filename = "ICA_keys.json"

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

    print(f"P_ICA keys generated and saved :)")

def Generate_ICA_CSR(pk, sk, algorithm):
    if algorithm not in SIG_ALGS_OIDS:
        raise ValueError(f"""Algorithm {algorithm} not supported by the code\n
                         From  function: Generate_ICA_P_CSR""")


    pub_key_bitstring = core.OctetBitString(pk)

    CSR_info = csr.CertificationRequestInfo({
        'version': 'v1',
        'subject': x509.Name.build({
            'common_name': 'ICA',
            'title': 'Clinic_ICA',
            'business_category': 'ICA_CSR'
        }),
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

    print("ICA_CSR generated :)")
    return CSR_PEM

def ICA_Extract_data_from_CSR(csr_data):

    if isinstance(csr_data, str):
       csr_data_bytes = csr_data.encode("utf-8")
    elif isinstance(csr_data, (bytes, bytearray, memoryview)):
         csr_data_bytes = bytes(csr_data)
    else:
        raise TypeError( f"CSR data must be str or bytes-like, got {type(csr_data)}")


    if pem.detect(csr_data_bytes):
        type_name, headers, der_bytes = pem.unarmor(csr_data_bytes)
        request = csr.CertificationRequest.load(der_bytes)
    else:
        print("Error: File is not a valid PEM.")
        return

    info = request['certification_request_info']

    CSR_INFO = info.dump()
    subject = info['subject'] 
    
    oid = info['subject_pk_info']['algorithm']['algorithm'].native
    
    public_key_information = info['subject_pk_info'] 
    
    public_key_bytes = info['subject_pk_info']['public_key'].native
    
    signature = request['signature'].native

    if oid not in OID_TO_ALGORITHM:
        print(f"Error: Unknown Algorithm OID {oid}")
        return

    CSR_algo_module = OID_TO_ALGORITHM[oid]

    return CSR_algo_module, CSR_INFO, subject, oid, public_key_bytes, signature, public_key_information

def ICA_Issue_Certificate(CSR,ICA_CRT_PEM,filename): 
    pk,sk,algorithm=Read_Keys()

    if isinstance(ICA_CRT_PEM, str):
     ICA_CRT_PEM = ICA_CRT_PEM.encode("utf-8")

    if pem.detect(ICA_CRT_PEM):
     _, _, der_bytes = pem.unarmor(ICA_CRT_PEM)
    else:
     der_bytes = ICA_CRT_PEM

    ica_cert = x509.Certificate.load(der_bytes)

    issuer = ica_cert['tbs_certificate']['subject']
    

    if os.path.exists(filename):
        os.remove(filename)
    

    CSR_ALGORITHM, CSR_INFORMATION, SUBJECT, OID_CSR_ALGORITHM, \
        PK_BYTES, SIGNATURE, PK_INFO = ICA_Extract_data_from_CSR(CSR)

    if not CSR_ALGORITHM.verify(PK_BYTES,CSR_INFORMATION,SIGNATURE):
        raise ValueError("CSR Signature not valid can not generate a certificate")


    now = datetime.datetime.now(datetime.timezone.utc)
    end = now + datetime.timedelta(days=365)



    ICA_signature_algo = x509.SignedDigestAlgorithm({
        'algorithm': SIG_ALGS_OIDS[algorithm],
        'parameters': None
    })


    to_be_signed_cert = x509.TbsCertificate({
        'version': 'v3',
        'serial_number': secrets.randbits(128),
        'signature': ICA_signature_algo,
        'issuer': issuer,
        'validity': x509.Validity({
            'not_before': x509.Time({'utc_time': now}),
            'not_after':  x509.Time({'utc_time': end})
        }),
        'subject': SUBJECT,  
        'subject_public_key_info': PK_INFO,
        'extensions': [
            x509.Extension({
                'extn_id': 'basic_constraints',
                'critical': True,
                'extn_value': x509.BasicConstraints({
                    'ca': False
                })
            }),
            x509.Extension({
                'extn_id': 'key_usage',
                'critical': True,
                'extn_value': x509.KeyUsage({'digital_signature'})
            })
        ]
    })


    to_be_signed_bytes = to_be_signed_cert.dump()
    
    print(f"Signing Certificate with ICA Key ({algorithm.__name__})...")

    if isinstance(sk, tuple):
      sk = sk[0]
    if isinstance(sk, memoryview):
      sk = bytes(sk)
    elif not isinstance(sk, bytes):
       raise TypeError(f"sk must be bytes, got {type(sk)}")

    ICA_signature = algorithm.sign(secret_key=sk, message=to_be_signed_bytes)


    cert = x509.Certificate({
        'tbs_certificate': to_be_signed_cert,
        'signature_algorithm': ICA_signature_algo,
        'signature_value': ICA_signature
    })


    cert_pem = pem.armor('CERTIFICATE', cert.dump()).decode('utf-8')

       
    with open(filename, "w") as f:
        f.write(cert_pem)

    print("cert generated and saved successfully.")

    return cert_pem

def Read_Keys():
    filename = "ICA_keys.json"

    if not os.path.exists(filename):
        raise FileNotFoundError(f"{filename} not found")

    with open(filename, "r") as f:
        keys = json.load(f)

    pk = base64.b64decode(keys["public_key"])
    sk = base64.b64decode(keys["secret_key"])

    alg_name = keys["algorithm"]

    if alg_name not in NAME_TO_ALGORITHM:
        raise ValueError(f"Unknown algorithm: {alg_name}")

    algorithm = NAME_TO_ALGORITHM[alg_name]

    return pk, sk, algorithm

def create_token(): return os.urandom(32)

