# Author: Maya Thabet October 22nd 2026
import base64
import json
import os

import bcrypt, psycopg2
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from charm.toolbox.pairinggroup import PairingGroup, GT
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07

def Hash_password(TA,table):  
    TA.execute(f"""Select id, password_hash from {table};""")
    users = TA.fetchall()
    for id, raw_pass in users:
         password_bytes = bytes(raw_pass) 
         plain_password_str = password_bytes.decode('utf-8')
         hashed_pass_bytes = bcrypt.hashpw(plain_password_str.encode('utf-8'),salt=bcrypt.gensalt())
    
         TA.execute(f"""UPDATE {table}
         SET password_hash = %s
         WHERE id = %s;""",
          (hashed_pass_bytes, id))
    
    print(f"Hashed passwords for {table} table successfully.")
    
def hash_existing_password_for_user(TA, table, user_id):
    TA.execute(
        f"""
        SELECT password_hash
        FROM {table}
        WHERE id = %s;
        """,
        (user_id,)
    )

    row = TA.fetchone()
    if row is None:
        raise ValueError("User not found")

    plain_password_bytes = bytes(row[0])

    salt = bcrypt.gensalt()
    hashed_pass = bcrypt.hashpw(plain_password_bytes, salt)

    TA.execute(
        f"""
        UPDATE {table}
        SET password_hash = %s
        WHERE id = %s;
        """,
        (hashed_pass, user_id)
    )


def Encrypt_Patient_Cols_AES(cur, col):
    cek = get_random_bytes(32)

    f_path = "col_keys.json"

    hex_string = "0x" + cek.hex()
    new_key_entry = {
        "col_name": col,
        "permanent_aes_key": hex_string
    }
    
    if os.path.exists(f_path):
        with open(f_path, "r") as f:
            try:
                data = json.load(f)
                if not isinstance(data, list):
                    data = [] 
            except json.JSONDecodeError:
                data = []
    else:
        data = []

    data = [item for item in data if item.get("col_name") != col]
    data.append(new_key_entry)

    with open(f_path, "w") as f:
        json.dump(data, f, indent=4)

    print(f"AES key made and saved the intermediate key for {col}")


    cur.execute(f"SELECT id, {col} FROM patients;")
    rows = cur.fetchall()

    for id, data_val in rows:
        iv = get_random_bytes(12)
        cipher = AES.new(cek, AES.MODE_GCM, nonce=iv)

        plaintext = json.dumps(data_val).encode("utf-8")
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)

        encrypted_data = json.dumps({
            "EncryptedData": base64.b64encode(ciphertext).decode(),
            "IV": base64.b64encode(iv).decode(),
            "Tag": base64.b64encode(tag).decode()
        })

        cur.execute(
            f"UPDATE patients SET {col} = %s WHERE id = %s;",
            (encrypted_data, id)
        )

    print(f"AES Key {col}:{cek}")


def Drop_Tables(cur):
    cur.execute("DROP TABLE IF EXISTS Appointments;")
    cur.execute("DROP TABLE IF EXISTS patients;")
    cur.execute("DROP TABLE IF EXISTS doctors;")
    cur.execute("DROP TABLE IF EXISTS Nurses;")
    cur.execute("DROP TABLE IF EXISTS Secretaries;")
    

    print("All tables dropped successfully.")

    cur.execute("""CREATE TABLE Secretaries ( 
     id SERIAL PRIMARY KEY,
     username VARCHAR(100) NOT NULL,
     password_hash BYTEA NOT NULL,
     phone_number VARCHAR(15),
     specialty TEXT,
     name TEXT);""")

    cur.execute("""INSERT INTO Secretaries (username, password_hash, phone_number, specialty , name)
      VALUES 
      ('marycain', 'marycain' , '987654321321' ,'Any' ,'Mary Cain'),
      ('harrylark', 'harrylark' , '45689512365' , 'Any' , 'Harry Lark');""")



    cur.execute("""CREATE TABLE nurses (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    specialty VARCHAR(100) NOT NULL,
    phone_number VARCHAR(15),
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash BYTEA NOT NULL,
    secretary_id INT REFERENCES Secretaries(id));""")

    cur.execute("""INSERT INTO Nurses (name, specialty, phone_number, username, password_hash, secretary_id)
    VALUES
    ('N. Niki Nikos', 'Cardiologist', '45698745126','niki', 'niki', 1),
    ('N. George Maragkopoulos', 'Orthopedic','78954621364', 'george', 'george', 2);""")


    
    cur.execute("""CREATE TABLE doctors (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    specialty VARCHAR(100) NOT NULL,
    phone_number VARCHAR(15),
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash BYTEA NOT NULL,
    secretary_id INT REFERENCES Secretaries(id),
    nurse_id INT REFERENCES Nurses(id));""")

    cur.execute("""INSERT INTO Doctors (name, specialty,phone_number, username, password_hash, secretary_id , nurse_id)
    VALUES
    ('Dr. John Smith', 'Cardiologist', '45698745126','drjohn', 'drjohn', 1,1),
    ('Dr. Mark Samson', 'Cardiologist','95486113217','drmark','drmark', 1,1),
    
    ('Dr. Maria Lopez', 'Orthopedic','78954621364', 'drmaria', 'drmaria', 2,2),
    ('Dr. Nagy Thabet', 'Orthopedic','24569874561', 'drnagy', 'drnagy', 2,2);""")
    
    
    cur.execute("""CREATE TABLE patients (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    age INTEGER,
    personal_info JSONB,
    Cardiology JSONB,
    Orthopedics JSONB);""")

    cur.execute("""
INSERT INTO patients (name, age, personal_info, Cardiology, Orthopedics)
VALUES 
('Maya Tom', 26, 
 jsonb_build_object(
  'phone_number', '+201023457891',
  'email', 'm.tom@gmail.com'
  )
 ,
 jsonb_build_object(
   'min_blood_pressure', 80,
   'max_blood_pressure', 100
 ),
 jsonb_build_object(
   'fracture_history', true,
   'recent_fracture', 'left arm',
   'joint_conditions', ARRAY['wrist pain', 'knee pain']
 )
),

('Lana Drake', 14, 
 jsonb_build_object(
  'phone_number', '+306912345678',
  'email', 'lana@gmail.com'
  ),
 NULL,
 jsonb_build_object(
   'fracture_history', true,
   'recent_fracture', 'clavicle'
 )
),

('Mike Steive', 50, 
 jsonb_build_object(
  'phone_number', '+306998754321',
  'email', 'mikes@msn.com'
  )
,
 jsonb_build_object(
   'min_blood_pressure', 90,
   'max_blood_pressure', 150,
   'min_normal_heart_rate', 80,
   'max_normal_heart_rate', 180
 ),
 jsonb_build_object(
   'joint_conditions', ARRAY['hip pain', 'knee pain']
 )
);""")
    
    cur.execute("""CREATE TABLE Appointments (
    what_time TIMESTAMP,
    doctor_id INT NOT NULL REFERENCES doctors(id) ,
    patient_id INT NOT NULL REFERENCES patients(id),
    PRIMARY KEY (doctor_id, patient_id, what_time));""")
    
    cur.execute("""
insert into Appointments(patient_id, doctor_id, what_time)
VALUES
(1,2,'2026-05-25 19:00:00'),
(1,4,'2026-05-23 16:00:00'),

(2,4,'2026-05-25 19:00:00'),

(3,1, '2026-05-23 16:00:00'),
(3,3, '2026-05-24 15:30:00');""")

    print("All tables created and populated successfully.")



def connection_to_DB(): 
 con = psycopg2.connect(
    host="clinic-db",
    port=5432,
    dbname="clinic",
    user="postgres",
    password="postgres")
 cur = con.cursor()
 return cur,con


if __name__ == "__main__": 
    cur,con=connection_to_DB()

    Drop_Tables(cur)
    Hash_password(cur,"Secretaries")
    Hash_password(cur,"nurses")
    Hash_password(cur,"doctors")


    Encrypt_Patient_Cols_AES(cur,"Cardiology")
    Encrypt_Patient_Cols_AES(cur,"Orthopedics")
    Encrypt_Patient_Cols_AES(cur,"personal_info")

    con.commit()
    cur.close()