# local/utils/license_client.py
from dotenv import load_dotenv
import os
import base64
import requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
import jwt
import time

load_dotenv()

CENTRAL_BASE = os.getenv("CENTRAL_BASE", "https://localhost:7000")
BOOTSTRAP_TOKEN = os.getenv("LICENSE_BOOTSTRAP_TOKEN")
LOCAL_KEYS_DIR = os.getenv("LOCAL_KEYS_DIR", "/var/lib/codesense/license")

def ensure_local_keys_dir():
    os.makedirs(LOCAL_KEYS_DIR, exist_ok=True)
    os.chmod(LOCAL_KEYS_DIR, 0o700)

def generate_local_keypair():
    ensure_local_keys_dir()
    sk = Ed25519PrivateKey.generate()
    sk_pem = sk.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    pk_pem = sk.public_key().public_bytes(Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

    with open(os.path.join(LOCAL_KEYS_DIR, "local_sk.pem"), "wb") as f:
        f.write(sk_pem)
    os.chmod(os.path.join(LOCAL_KEYS_DIR, "local_sk.pem"), 0o600)
    with open(os.path.join(LOCAL_KEYS_DIR, "local_pk.pem"), "wb") as f:
        f.write(pk_pem)
    return sk, pk_pem.decode()

def load_local_sk():
    with open(os.path.join(LOCAL_KEYS_DIR, "local_sk.pem"), "rb") as f:
        data = f.read()
    return serialization.load_pem_private_key(data, password=None)

def provision(org_id, license_id, local_id, hw_fp=None):
    # ensure keypair exists
    if not os.path.exists(os.path.join(LOCAL_KEYS_DIR, "local_sk.pem")):
        sk, pk_pem = generate_local_keypair()
    else:
        sk = load_local_sk()
        pk_pem = open(os.path.join(LOCAL_KEYS_DIR, "local_pk.pem")).read()

    body = {
        "org_id": org_id,
        "license_id": license_id,
        "local_id": local_id,
        "local_pubkey_pem": pk_pem,
        "hw_fp": hw_fp
    }
    headers = {"Authorization": f"Bearer {BOOTSTRAP_TOKEN}"}
    r = requests.post(CENTRAL_BASE + "/api/v1/provision", json=body, headers=headers, timeout=15, verify=True)
    r.raise_for_status()
    resp = r.json()
    # store provisioning_jwt and central root pub
    with open(os.path.join(LOCAL_KEYS_DIR, "provisioning_jwt.txt"), "w") as f:
        f.write(resp["provisioning_jwt"])
    with open(os.path.join(LOCAL_KEYS_DIR, "central_root_pk.pem"), "w") as f:
        f.write(resp["central_root_public_pem"])
    return resp

def get_challenge(local_id):
    r = requests.get(CENTRAL_BASE + f"/api/v1/challenge?local_id={local_id}", timeout=10, verify=True)
    r.raise_for_status()
    return r.json()["nonce"]

def request_assertion(local_id):
    # load
    sk = load_local_sk()
    prov_jwt = open(os.path.join(LOCAL_KEYS_DIR, "provisioning_jwt.txt")).read().strip()
    nonce = get_challenge(local_id)
    sig = sk.sign(nonce.encode())
    signed_nonce_b64 = base64.urlsafe_b64encode(sig).decode()

    body = {
        "local_id": local_id,
        "provisioning_jwt": prov_jwt,
        "nonce": nonce,
        "signed_nonce": signed_nonce_b64
    }
    r = requests.post(CENTRAL_BASE + "/api/v1/license/assert", json=body, timeout=15, verify=True)
    r.raise_for_status()
    resp = r.json()
    # store assertion
    with open(os.path.join(LOCAL_KEYS_DIR, "assertion_jwt.txt"), "w") as f:
        f.write(resp["assertion_jwt"])
    with open(os.path.join(LOCAL_KEYS_DIR, "central_root_pk.pem"), "w") as f:
        f.write(resp["central_root_public_pem"])
    return resp

def verify_assertion_local():
    prov_jwt = open(os.path.join(LOCAL_KEYS_DIR, "provisioning_jwt.txt")).read().strip()
    assertion_jwt = open(os.path.join(LOCAL_KEYS_DIR, "assertion_jwt.txt")).read().strip()
    central_pk = open(os.path.join(LOCAL_KEYS_DIR, "central_root_pk.pem")).read().encode()
    # verify using pyjwt
    payload = jwt.decode(assertion_jwt, central_pk, algorithms=["EdDSA"])
    # basic checks
    now = int(time.time())
    if payload.get("nbf", 0) > now or payload.get("exp", 0) < now:
        raise RuntimeError("Assertion expired or not yet valid")
    # verify bind.prov_hash matches our provisioning_jwt
    import hashlib
    prov_hash = hashlib.sha256(prov_jwt.encode()).hexdigest()
    if payload.get("bind", {}).get("prov_hash") != prov_hash:
        raise RuntimeError("Assertion does not bind to local provisioning cert")
    return payload
