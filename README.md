# How to build the DB container 
docker run -d --name clinic-db --network (Your created Network) -p 5433:5432 -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=clinic postgres:16

# Encrypting DB container
First Run the TA and the DB containers to addd and encrypt the data in the database.

Open the TA container in Bash and run : python 3 DB_related.py

# Adjustments in the ASN1
 Edit  (keys.py) file in asn1. search for : def _public_key_spec(self). Insert the folowing:
   # -----------------PQC ---------------------#
   # ML-DSA (Dilithium) - RAW OIDS 
     '2.16.840.1.101.3.4.3.17': (OctetBitString, None), # ml_dsa_44 
     '2.16.840.1.101.3.4.3.18': (OctetBitString, None), # ml_dsa_65 
     '2.16.840.1.101.3.4.3.19': (OctetBitString, None), # ml_dsa_87

  # (SPHINCS+) - RAW OIDS
     '2.16.840.1.101.3.4.3.21': (OctetBitString, None), # sha2_128f
     '2.16.840.1.101.3.4.3.23': (OctetBitString, None), # sha2_192f
     '2.16.840.1.101.3.4.3.25': (OctetBitString, None), # sha2_256f
  # --------------------------------
