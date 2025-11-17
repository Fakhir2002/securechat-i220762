import os
import socket
import json
import threading
from typing import Dict, Any, Tuple

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    # If python-dotenv isn't installed, it's fine as long as env vars are set some other way
    pass

from cryptography.hazmat.primitives import hashes, serialization

from app.common.utils import b64_encode, b64_decode, now_ms
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
    load_public_key_from_cert,
    rsa_verify,
)
from app.storage.db import create_user, verify_user
from app.storage.transcript import (
    Transcript,
    make_session_receipt,
    fingerprint_cert_der,
)


# ------------- Socket helpers -------------


def send_json(sock: socket.socket, obj: Dict[str, Any]) -> None:
    """
    Send a single JSON object terminated by newline.
    """
    data = (json.dumps(obj) + "\n").encode("utf-8")
    sock.sendall(data)


def recv_json(sock: socket.socket) -> Dict[str, Any]:
    """
    Receive until newline and parse as JSON.
    """
    buf = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("Connection closed by peer")
        buf += chunk
        if b"\n" in buf:
            line, _, rest = buf.partition(b"\n")
            # Note: rest is discarded; protocol is one JSON per line
            return json.loads(line.decode("utf-8"))


# ------------- Config & cert loading -------------


def load_env_config() -> Tuple[str, int, str, str, str]:
    host = os.getenv("SERVER_HOST", "127.0.0.1")
    port = int(os.getenv("SERVER_PORT", "9000"))

    server_cert_path = os.getenv("SERVER_CERT", "certs/server.cert.pem")
    server_key_path = os.getenv("SERVER_KEY", "certs/server.key.pem")
    ca_cert_path = os.getenv("CA_CERT", "certs/ca.cert.pem")

    return host, port, server_cert_path, server_key_path, ca_cert_path


def load_pem(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


# ------------- Auth over temporary DH + AES -------------


def handle_auth_phase(sock: socket.socket, temp_key: bytes) -> str:
    """
    Auth phase happens after temporary DH key is derived.

    We expect a message:

        {
          "type": "auth",
          "mode": "register" | "login",
          "ct": base64 AES-128( inner_json )
        }

    inner_json for register:
        { "mode":"register", "email":"", "username":"", "password":"" }

    inner_json for login:
        { "mode":"login", "email":"", "password":"" }

    Returns the authenticated username (str).
    """
    msg = recv_json(sock)
    if msg.get("type") != "auth":
        raise ValueError("Expected auth message")

    mode = msg.get("mode")
    ct_b64 = msg.get("ct")
    if not ct_b64 or mode not in ("register", "login"):
        raise ValueError("Invalid auth payload")

    ct = b64_decode(ct_b64)
    inner = aes_decrypt(temp_key, ct)
    inner_obj = json.loads(inner.decode("utf-8"))

    inner_mode = inner_obj.get("mode")
    if inner_mode != mode:
        raise ValueError("Auth mode mismatch")

    email = inner_obj.get("email")
    password = inner_obj.get("password")
    username = inner_obj.get("username")  # only for register

    if not email or not password:
        raise ValueError("Missing email or password")

    if mode == "register":
        if not username:
            raise ValueError("Missing username for registration")
        success = create_user(email=email, username=username, password=password)
        if not success:
            # email or username already exists
            send_json(sock, {"type": "auth_result", "status": "error", "reason": "exists"})
            raise ValueError("User already exists")
        send_json(sock, {"type": "auth_result", "status": "ok", "mode": "register"})
        return username

    # login
    verified_username = verify_user(email=email, password=password)
    if not verified_username:
        send_json(sock, {"type": "auth_result", "status": "error", "reason": "invalid"})
        raise ValueError("Invalid credentials")

    send_json(sock, {"type": "auth_result", "status": "ok", "mode": "login"})
    return verified_username


# ------------- Per-client handler -------------


def handle_client(conn: socket.socket, addr: Tuple[str, int],
                  server_cert_pem: bytes,
                  server_priv_key_path: str,
                  ca_cert_pem: bytes) -> None:
    print(f"[+] Connection from {addr}")

    try:
        # Load server private key (for message signing, receipts, etc.)
        # For now, server only verifies client's signatures; receipts are signed at the end.
        server_priv_key = load_private_key(server_priv_key_path)

        # -------------------------
        # 1) Receive client's Hello + cert
        # -------------------------
        hello_raw = recv_json(conn)
        if hello_raw.get("type") != "hello":
            raise ValueError("Expected hello message from client")

        hello = HelloMsg(**hello_raw)

        client_cert_pem = hello.client_cert.encode("utf-8")
        client_cert = validate_peer_cert(
            peer_cert_pem=client_cert_pem,
            ca_cert_pem=ca_cert_pem,
            expected_cn="client.local",  # adjust if different CN used
        )
        print("[PKI] Client certificate validated")

        # Compute fingerprint of client cert (DER) for transcript logging
        client_cert_der = client_cert.public_bytes(serialization.Encoding.DER)
        client_fpr_hex = fingerprint_cert_der(client_cert_der)

        # -------------------------
        # 2) Send ServerHello with server cert
        # -------------------------
        server_nonce = os.urandom(16)
        server_hello = ServerHello(
            server_cert=server_cert_pem.decode("utf-8"),
            nonce=b64_encode(server_nonce),
        )
        send_json(conn, server_hello.dict())
        print("[PKI] Sent server_hello with server certificate")

        # -------------------------
        # 3) Temporary DH for auth (registration/login)
        #    Client initiates: DhClient (g, p, A)
        # -------------------------
        dh_client_raw = recv_json(conn)
        if dh_client_raw.get("type") != "dh_client":
            raise ValueError("Expected dh_client for auth phase")

        dh_client = DhClient(**dh_client_raw)
        g = dh_client.g
        p = dh_client.p
        A = dh_client.A

        if p <= 2 or g <= 1:
            raise ValueError("Invalid DH parameters")

        b = generate_private(p)
        B = compute_public(g, p, b)
        Ks = compute_shared(A, p, b)
        temp_key = derive_aes_key_from_shared(Ks)
        print("[DH] Temporary auth key derived.")

        dh_server = DhServer(B=B)
        send_json(conn, dh_server.dict())
        print("[DH] Sent dh_server (auth phase)")

        # -------------------------
        # 4) Auth Phase (under temp_key)
        # -------------------------
        username = handle_auth_phase(conn, temp_key)
        print(f"[AUTH] Authenticated user: {username}")

        # -------------------------
        # 5) Second DH for chat session key
        # -------------------------
        dh_client_raw2 = recv_json(conn)
        if dh_client_raw2.get("type") != "dh_client":
            raise ValueError("Expected dh_client for chat session")

        dh_client2 = DhClient(**dh_client_raw2)
        g2 = dh_client2.g
        p2 = dh_client2.p
        A2 = dh_client2.A

        if p2 <= 2 or g2 <= 1:
            raise ValueError("Invalid DH parameters (session)")

        b2 = generate_private(p2)
        B2 = compute_public(g2, p2, b2)
        Ks2 = compute_shared(A2, p2, b2)
        session_key = derive_aes_key_from_shared(Ks2)
        print("[DH] Session key derived.")

        dh_server2 = DhServer(B=B2)
        send_json(conn, dh_server2.dict())
        print("[DH] Sent dh_server (session key)")

        # -------------------------
        # 6) Prepare for encrypted chat
        # -------------------------
        # Server will verify client's per-message signatures using client's public key
        client_public_key = client_cert.public_key()

        # Initialize transcript
        transcript = Transcript.new(prefix=f"server_{username}")
        first_seq = None
        last_seq = None

        print("[CHAT] Ready to receive encrypted messages from client.")
        send_json(conn, {"type": "chat_ready"})

        # -------------------------
        # 7) Receive chat messages until client sends {"type": "bye"}
        # -------------------------
        while True:
            msg = recv_json(conn)

            if msg.get("type") == "bye":
                print("[CHAT] Client requested to close session.")
                break

            if msg.get("type") != "msg":
                print(f"[WARN] Ignoring unexpected message: {msg.get('type')}")
                continue

            chat = ChatMsg(**msg)
            seqno = chat.seqno
            ts = chat.ts
            ct_b64 = chat.ct
            sig_b64 = chat.sig

            # Track seqno for transcript boundaries
            if first_seq is None or seqno < first_seq:
                first_seq = seqno
            if last_seq is None or seqno > last_seq:
                last_seq = seqno

            ct = b64_decode(ct_b64)
            sig = b64_decode(sig_b64)

            # Verify signature: SHA256(seqno||ts||ct)
            seq_bytes = seqno.to_bytes(8, "big", signed=False)
            ts_bytes = ts.to_bytes(8, "big", signed=False)
            digest = hashes.Hash(hashes.SHA256())
            digest.update(seq_bytes + ts_bytes + ct)
            h = digest.finalize()

            if not rsa_verify(client_public_key, h, sig):
                print("[SIG_FAIL] Invalid signature, dropping message.")
                continue

            # Decrypt
            try:
                plaintext = aes_decrypt(session_key, ct)
            except Exception as e:
                print(f"[DECRYPT_FAIL] {e}")
                continue

            text = plaintext.decode("utf-8", errors="replace")
            print(f"[{username}] #{seqno} @ {ts}: {text}")

            # Append to transcript
            transcript.append(
                seqno=seqno,
                ts_ms=ts,
                ct_b64=ct_b64,
                sig_b64=sig_b64,
                peer_fpr_hex=client_fpr_hex,
            )

        # -------------------------
        # 8) Non-repudiation: SessionReceipt
        # -------------------------
        if first_seq is None:
            first_seq = 0
        if last_seq is None:
            last_seq = 0

        receipt = make_session_receipt(
            transcript=transcript,
            peer_role="server",
            first_seq=first_seq,
            last_seq=last_seq,
            priv_key_path=server_priv_key_path,
        )

        # Send receipt to client
        send_json(conn, receipt)
        print("[NR] SessionReceipt sent to client.")
        print("[*] Session closed.")

    except Exception as e:
        print(f"[ERROR] {addr}: {e}")
    finally:
        conn.close()
        print(f"[-] Connection closed: {addr}")


# ------------- Main server loop -------------


def main():
    host, port, server_cert_path, server_key_path, ca_cert_path = load_env_config()

    server_cert_pem = load_pem(server_cert_path)
    ca_cert_pem = load_pem(ca_cert_path)

    print(f"[CONFIG] Listening on {host}:{port}")
    print(f"[CONFIG] Server cert: {server_cert_path}")
    print(f"[CONFIG] CA cert: {ca_cert_path}")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen(5)
        print("[SERVER] Waiting for connections...")

        while True:
            conn, addr = s.accept()
            # Handle each client in its own thread (simple concurrency)
            t = threading.Thread(
                target=handle_client,
                args=(conn, addr, server_cert_pem, server_key_path, ca_cert_pem),
                daemon=True,
            )
            t.start()


if __name__ == "__main__":
    main()
