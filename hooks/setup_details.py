from cryptography.fernet import Fernet

FERNET_KEY=b"1jP-Gs2XJlNncgPSOqOVMlr72Rj-OzAqnXH5nx-v1Xo="
ENCRYPTED_SONAR=b"gAAAAABobkxIJB4jzR8oBVfVJKOWZwbKbwQKyI_ZgD55TJp7bBR_M18vJVq31XnjPAUwi6pOjYyQP44uYM0xHA3ljqREyk7i3XgyBnQ2Zskr2Gl6nH8AAFgmLOOiPG33uWf9yAcNdhH8"
ENCRYPTED_HF=b"gAAAAABobkxIDtB4cu4Vgjrlaza6xq2wbWNFNJk2GJX5RBz2acTg9pwqO_tIcdm5tkAzFx6KK6V5bJajkFBXgUzaqcpGcMMAdoycHrGPuCS4StXlbXiowPey8xYBJPFMpaxMk95fqa14"

def get_decrypted_tokens():
    f = Fernet(FERNET_KEY)
    sonar_token = f.decrypt(ENCRYPTED_SONAR).decode()
    hf_token = f.decrypt(ENCRYPTED_HF).decode()
    
    return {
        "SONAR_TOKEN": sonar_token,
        "HF_TOKEN": hf_token
    }
