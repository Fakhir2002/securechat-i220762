"""
Pydantic message models for SecureChat protocol.
These are the ONLY structures exchanged between client and server.
"""

from pydantic import BaseModel
from typing import Optional


# -------------------------
# Control Plane (certs + login)
# -------------------------

class HelloMsg(BaseModel):
    type: str = "hello"
    client_cert: str   # PEM string
    nonce: str         # base64


class ServerHello(BaseModel):
    type: str = "server_hello"
    server_cert: str   # PEM string
    nonce: str         # base64


class RegisterMsg(BaseModel):
    type: str = "register"
    email: str
    username: str
    pwd: str      # base64(AES(ct))
    salt: Optional[str] = None  # not used by client; server generates


class LoginMsg(BaseModel):
    type: str = "login"
    email: str
    pwd: str       # base64(AES(ct))
    nonce: str     # optional extra freshness


# -------------------------
# Diffie–Hellman exchange
# -------------------------

class DhClient(BaseModel):
    type: str = "dh_client"
    g: int
    p: int
    A: int         # g^a mod p


class DhServer(BaseModel):
    type: str = "dh_server"
    B: int         # g^b mod p


# -------------------------
# Encrypted chat message
# -------------------------

class ChatMsg(BaseModel):
    type: str = "msg"
    seqno: int
    ts: int
    ct: str      # base64(ciphertext)
    sig: str     # base64(RSA signature of sha256(seqno||ts||ct))


# -------------------------
# Session Receipt
# -------------------------

class ReceiptMsg(BaseModel):
    type: str = "receipt"
    peer: str                 # "client" or "server"
    first_seq: int
    last_seq: int
    transcript_sha256: str
    sig: str                 # base64 RSA signature
