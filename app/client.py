import os
import socket
import json
import threading

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

from cryptography.hazmat.primitives import hashes, serialization

from app.common.utils import (
    b64_encode,
    b64_decode,
    now_ms,
)
from app.common.protocol import (
    HelloMsg,
    ServerHello,
    DhClient,
    DhServer,
    ChatMsg,
)
from app.crypto.aes import aes_encrypt, aes_decrypt
from app.crypto.dh import (
    generate_private,
    compute_public,
    compute_shared,
    derive_aes_key_from_shared,
)
from app.crypto.pki import validate_peer_cert
from app.crypto.sign import (
    load_private_key,
    rsa_sign,
)
from app.storage.transcript import (
    Transcript,
    make_session_receipt,
    fingerprint_cert_der,
)


# ------------------------ Socket helpers ------------------------

def send_json(sock: socket.socket, obj: dict) -> None:
    data = (json.dumps(obj) + "\n").encode("utf-8")
    sock.sendall(data)


def recv_json(sock: socket.socket) -> dict:
    buf = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("Server closed the connection")
        buf += chunk
        if b"\n" in buf:
            line, _, rest = buf.partition(b"\n")
            return json.loads(line.decode("utf-8"))


# ------------------------ Env & File Loading ------------------------

def load_env():
    host = os.getenv("SERVER_HOST", "127.0.0.1")
    port = int(os.getenv("SERVER_PORT", "9000"))

    client_cert_path = os.getenv("CLIENT_CERT", "certs/client.cert.pem")
    client_key_path = os.getenv("CLIENT_KEY", "certs/client.key.pem")
    ca_cert_path = os.getenv("CA_CERT", "certs/ca.cert.pem")

    return host, port, client_cert_path, client_key_path, ca_cert_path


def load_pem(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


# ------------------------ Temporary DH Auth Phase ------------------------

def do_temp_dh(sock: socket.socket) -> bytes:
    """
    Client initiates temporary DH to derive AES key for authentication phase.
    """
    # Use a small safe prime (example) or load a bigger one—assignment allows any known safe value.
    # For simplicity, use a 2048-bit safe prime? To keep code simple, use small demo values:
    p = 0xFFFFFFFEFFFFEE37  # You can replace with a stronger prime if you wish
    g = 2

    a = generate_private(p)
    A = compute_public(g, p, a)

    dh_client = DhClient(g=g, p=p, A=A)
    send_json(sock, dh_client.dict())

    resp = recv_json(sock)
    if resp.get("type") != "dh_server":
        raise ValueError("Expected dh_server")

    B = resp["B"]
    Ks = compute_shared(B, p, a)

    temp_key = derive_aes_key_from_shared(Ks)
    print("[DH] Temporary auth key established.")

    return temp_key


def auth_register(sock: socket.socket, temp_key: bytes):
    email = input("Enter email: ").strip()
    username = input("Choose username: ").strip()
    password = input("Choose password: ").strip()

    inner = json.dumps({
        "mode": "register",
        "email": email,
        "username": username,
        "password": password
    }).encode("utf-8")

    ct = aes_encrypt(temp_key, inner)
    msg = {
        "type": "auth",
        "mode": "register",
        "ct": b64_encode(ct)
    }
    send_json(sock, msg)

    resp = recv_json(sock)
    if resp.get("status") != "ok":
        print("❌ Registration failed:", resp)
        raise ValueError("Registration failed")

    print("✅ Registered successfully!")
    return username


def auth_login(sock: socket.socket, temp_key: bytes):
    email = input("Email: ").strip()
    password = input("Password: ").strip()

    inner = json.dumps({
        "mode": "login",
        "email": email,
        "password": password
    }).encode("utf-8")

    ct = aes_encrypt(temp_key, inner)
    msg = {
        "type": "auth",
        "mode": "login",
        "ct": b64_encode(ct)
    }
    send_json(sock, msg)

    resp = recv_json(sock)
    if resp.get("status") != "ok":
        print("❌ Login failed:", resp)
        raise ValueError("Invalid credentials")

    print("✅ Login success!")
    return email  # server returns username but we use email for now


# ------------------------ Session DH Key ------------------------

def do_session_dh(sock: socket.socket) -> bytes:
    p = 0xFFFFFFFEFFFFEE37
    g = 2

    a = generate_private(p)
    A = compute_public(g, p, a)

    dh_client = DhClient(g=g, p=p, A=A)
    send_json(sock, dh_client.dict())

    resp = recv_json(sock)
    if resp.get("type") != "dh_server":
        raise ValueError("Expected dh_server (session)")

    B = resp["B"]
    Ks = compute_shared(B, p, a)
    session_key = derive_aes_key_from_shared(Ks)
    print("[DH] Session key established.")

    return session_key


# ------------------------ Chat Loop ------------------------

def chat_loop(sock: socket.socket, session_key: bytes, client_priv_key, server_fpr: str):
    seqno = 1
    transcript = Transcript.new(prefix="client")

    print("📨 Chat ready! Type your message. Type /bye to exit.\n")

    while True:
        text = input("> ")

        if text.strip() == "/bye":
            send_json(sock, {"type": "bye"})
            break

        plaintext = text.encode("utf-8")
        ct = aes_encrypt(session_key, plaintext)

        ts = now_ms()
        ct_b64 = b64_encode(ct)

        # Build signature digest
        seq_bytes = seqno.to_bytes(8, "big")
        ts_bytes = ts.to_bytes(8, "big")

        digest = hashes.Hash(hashes.SHA256())
        digest.update(seq_bytes + ts_bytes + ct)
        h = digest.finalize()

        sig = rsa_sign(client_priv_key, h)
        sig_b64 = b64_encode(sig)

        msg = ChatMsg(
            seqno=seqno,
            ts=ts,
            ct=ct_b64,
            sig=sig_b64,
        )
        send_json(sock, msg.dict())

        transcript.append(
            seqno=seqno,
            ts_ms=ts,
            ct_b64=ct_b64,
            sig_b64=sig_b64,
            peer_fpr_hex=server_fpr,
        )

        seqno += 1

    # Receive receipt
    receipt = recv_json(sock)
    print("\n📄 Received SessionReceipt from server:")
    print(json.dumps(receipt, indent=2))

    # Save local receipt
    local_receipt = make_session_receipt(
        transcript=transcript,
        peer_role="client",
        first_seq=1,
        last_seq=seqno - 1,
        priv_key_path=os.getenv("CLIENT_KEY"),
    )

    print("\n📄 Generated client-side SessionReceipt:")
    print(json.dumps(local_receipt, indent=2))
    print("✔ Session closed.")


# ------------------------ Main client flow ------------------------

def main():
    host, port, client_cert_path, client_key_path, ca_cert_path = load_env()

    client_cert_pem = load_pem(client_cert_path)
    ca_cert_pem = load_pem(ca_cert_path)

    client_priv_key = load_private_key(client_key_path)

    print(f"[CONFIG] Connecting to {host}:{port}...")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        print("[NET] Connected.")

        # 1) Send Hello with client cert
        nonce = os.urandom(16)
        hello = HelloMsg(
            client_cert=client_cert_pem.decode("utf-8"),
            nonce=b64_encode(nonce)
        )
        send_json(s, hello.dict())
        print("[PKI] Sent hello with client certificate.")

        # 2) Receive ServerHello + validate cert
        sh_raw = recv_json(s)
        sh = ServerHello(**sh_raw)
        server_cert_pem = sh.server_cert.encode("utf-8")

        server_cert = validate_peer_cert(
            peer_cert_pem=server_cert_pem,
            ca_cert_pem=ca_cert_pem,
            expected_cn="server.local",
        )
        print("[PKI] Server certificate validated.")

        server_cert_der = server_cert.public_bytes(serialization.Encoding.DER)
        server_fpr_hex = fingerprint_cert_der(server_cert_der)

        # 3) Temporary DH → AES auth key
        temp_key = do_temp_dh(s)

        # 4) Choose: register or login
        mode = input("Choose mode (login/register): ").strip().lower()
        if mode == "register":
            username = auth_register(s, temp_key)
        else:
            username = auth_login(s, temp_key)

        # 5) Session DH
        session_key = do_session_dh(s)

        # 6) Wait for server ready msg
        ready = recv_json(s)
        if ready.get("type") != "chat_ready":
            raise ValueError("Server did not send chat_ready")

        # 7) Chat
        chat_loop(s, session_key, client_priv_key, server_fpr_hex)


if __name__ == "__main__":
    main()
