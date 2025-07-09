from cryptography.fernet import Fernet

FERNET_KEY=b"t2DsqlhL-prM2RDhz8PatUUyYzl1hP3iOtQByjZBxZA="
ENCRYPTED_SONAR=b"gAAAAABobgF2Z1MhI4lSmKlY-STb8KSxSOtHkt1iXVUTRufZaWHtYhLHU6PWSUsysN_ZB-vgprrghbimua0khqx3NCrXqSg8wF-zciuN7Vie6m6aixXkd8RMJOv0w3bq6PirYH9_Wyof"
ENCRYPTED_HF=b"gAAAAABobgF2ixuEL018zpOzVuD_VhoffaEulwJi0DFq6riTEpwnbvpOXfkdT4qDoHMrL5O5dTkRLRcL7sdW_lQeMM8SmvXo0L0yNNwYAzT4EtVv0xdoh8L0pdlHMIAnn5v5NvH_oMKE"

def get_decrypted_tokens():
    f = Fernet(FERNET_KEY)
    sonar_token = f.decrypt(ENCRYPTED_SONAR).decode()
    hf_token = f.decrypt(ENCRYPTED_HF).decode()
    
    return {
        "SONAR_TOKEN": sonar_token,
        "HF_TOKEN": hf_token
    }
