import io
import os
import time
import base64
import unittest
from pathlib import Path
from app import app, connect, stored_path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def verify_full_system_workflow():
    print("=" * 70)
    print("VAULTX COMPREHENSIVE END-TO-END WORKFLOW VERIFICATION")
    print("=" * 70)

    client = app.test_client()

    # -------------------------------------------------------------------------
    # STAGE 1: Client-Side AES-256-GCM Encryption & Upload
    # -------------------------------------------------------------------------
    print("\n[STAGE 1] Client-side AES-256-GCM Encryption & Upload...")
    original_secret = b"VAULTX_ZERO_KNOWLEDGE_SECRET_DOCUMENT_CONTENTS_2026_CONFIDENTIAL"
    original_filename = "financial_audit_2026.pdf"

    # Generate 256-bit AES key and 12-byte IV
    key = AESGCM.generate_key(bit_length=256)
    iv = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, original_secret, None)

    iv_b64 = base64.b64encode(iv).decode("utf-8")
    key_b64 = base64.b64encode(key).decode("utf-8")

    # Upload to server-blind vault
    upload_res = client.post("/api/upload", data={
        "file": (io.BytesIO(ciphertext), "encrypted.bin"),
        "iv": iv_b64,
        "original_filename": original_filename,
        "mime_type": "application/pdf",
        "expiry": "1d"
    })
    assert upload_res.status_code == 201, f"Upload failed: {upload_res.status_code}"
    upload_data = upload_res.get_json()
    file_id = upload_data["id"]
    expires_at = upload_data["expires_at"]
    print(f"  -> File sealed successfully! ID: {file_id}")
    print(f"  -> Ciphertext size on disk: {len(ciphertext)} bytes")
    print(f"  -> Link expires at Unix: {expires_at}")

    # Verify zero keys in database
    with connect() as conn:
        row = conn.execute("SELECT * FROM vault_files WHERE id = ?", (file_id,)).fetchone()
        assert row is not None
        assert key_b64 not in str(dict(row)), "Zero-knowledge violation: Key found in database row!"
    print("  -> Verified: Zero keys stored in server database (Zero-Knowledge intact)")

    # -------------------------------------------------------------------------
    # STAGE 2: Normal Secure Sharing Link Generation (No QR code)
    # -------------------------------------------------------------------------
    print("\n[STAGE 2] Secure Sharing Link Generation...")
    share_link = f"http://localhost:5000/f/{file_id}#{key_b64}"
    print(f"  -> Generated Sharing Link: {share_link}")
    print("  -> RFC 3986 client-side hash guarantee: Everything after '#' remains in browser RAM")

    # Verify dashboard template has NO QR modal
    dash_page = client.get("/dashboard")
    assert b"qrModal" not in dash_page.data, "QR modal should NOT be in dashboard HTML"
    assert b"qrcode" not in dash_page.data.lower(), "QR code references should NOT be in dashboard HTML"
    print("  -> Verified: QR code modal & display completely removed from UI")

    # -------------------------------------------------------------------------
    # STAGE 3: Recipient Access & Metadata Retrieval (Logs 'view' event)
    # -------------------------------------------------------------------------
    print("\n[STAGE 3] Recipient Access & Metadata Verification...")
    meta_res = client.get(f"/api/files/{file_id}/meta")
    assert meta_res.status_code == 200, f"Meta request failed: {meta_res.status_code}"
    meta_data = meta_res.get_json()
    assert meta_data["filename"] == original_filename
    assert meta_data["iv"] == iv_b64
    assert meta_data["remaining_seconds"] > 0
    print(f"  -> Metadata verified: {meta_data['filename']} ({meta_data['size']} bytes)")
    print(f"  -> Expiry Countdown remaining: {meta_data['remaining_seconds']} seconds")

    # -------------------------------------------------------------------------
    # STAGE 4: Download Encrypted Ciphertext (Logs 'download' event)
    # -------------------------------------------------------------------------
    print("\n[STAGE 4] Download Encrypted Ciphertext from Server...")
    dl_res = client.get(f"/api/files/{file_id}")
    assert dl_res.status_code == 200, f"Download failed: {dl_res.status_code}"
    downloaded_ciphertext = dl_res.data
    dl_res.close()
    assert downloaded_ciphertext == ciphertext, "Downloaded ciphertext does not match original uploaded ciphertext!"
    print(f"  -> Downloaded {len(downloaded_ciphertext)} bytes of raw AES-256-GCM ciphertext")

    # -------------------------------------------------------------------------
    # STAGE 5: Client-Side Decryption in volatile memory
    # -------------------------------------------------------------------------
    print("\n[STAGE 5] In-Browser Client Decryption...")
    decrypted_bytes = aesgcm.decrypt(iv, downloaded_ciphertext, None)
    assert decrypted_bytes == original_secret, "Decryption plaintext mismatch!"
    print(f"  -> Decryption successful! Plaintext: '{decrypted_bytes.decode()}'")

    # -------------------------------------------------------------------------
    # STAGE 6: Smart Security Score Verification
    # -------------------------------------------------------------------------
    print("\n[STAGE 6] Smart Security Score Evaluation...")
    score_res = client.get("/api/security-score")
    assert score_res.status_code == 200
    score_data = score_res.get_json()
    print(f"  -> Authentic Security Score: {score_data['total_score']}/{score_data['max_score']} (Grade: {score_data['grade']}, Status: {score_data['status']})")
    for check in score_data["checks"]:
        pass_symbol = "PASS" if check["passed"] else "FAIL"
        print(f"     * [{pass_symbol}] {check['name']}: {check['score']}/{check['max']} pts - {check['description']}")
    assert score_data["total_score"] >= 80, "Security score unexpectedly low"

    # -------------------------------------------------------------------------
    # STAGE 7: Emergency Revocation
    # -------------------------------------------------------------------------
    print("\n[STAGE 7] Emergency Revoke Execution...")
    fpath = stored_path(file_id)
    assert fpath.exists(), "Stored file should exist before revocation"

    revoke_res = client.post(f"/api/files/{file_id}/revoke")
    assert revoke_res.status_code == 200
    revoke_data = revoke_res.get_json()
    assert revoke_data["success"] is True
    print(f"  -> Revocation API response: {revoke_data['message']}")

    # Check physical ciphertext unlinked from disk
    assert not fpath.exists(), "CRITICAL: Physical ciphertext file MUST be unlinked from disk on revoke!"
    print("  -> Verified: Physical ciphertext file unlinked & purged from disk")

    # Check subsequent meta request returns 404 with revoked notice
    rev_meta_res = client.get(f"/api/files/{file_id}/meta")
    assert rev_meta_res.status_code == 404
    rev_meta_data = rev_meta_res.get_json()
    assert rev_meta_data.get("revoked") is True
    print(f"  -> Subsequent meta access rejected: {rev_meta_data['error']}")

    # Check subsequent download request rejected
    rev_dl_res = client.get(f"/api/files/{file_id}")
    assert rev_dl_res.status_code == 404
    print("  -> Subsequent download access rejected with HTTP 404")

    # -------------------------------------------------------------------------
    # STAGE 8: Suspicious Activity Alerts Detection
    # -------------------------------------------------------------------------
    print("\n[STAGE 8] Suspicious Activity Alerts & Threat Defense...")
    # Simulate additional failed attempts to reach threshold (>= 3)
    for _ in range(3):
        client.get(f"/api/files/{file_id}/meta")

    alerts_res = client.get("/api/security/alerts")
    assert alerts_res.status_code == 200
    alerts_data = alerts_res.get_json()
    print(f"  -> Threat Defense status: {alerts_data['threat_level']} ({alerts_data['count']} active warnings)")
    for alert in alerts_data["alerts"]:
        print(f"     ! [{alert['severity'].upper()}] {alert['title']}: {alert['message']}")

    # -------------------------------------------------------------------------
    # STAGE 9: Activity Timeline Verification
    # -------------------------------------------------------------------------
    print("\n[STAGE 9] Activity Timeline & Cryptographic Audit Trail...")
    dash_res = client.get("/api/files")
    assert dash_res.status_code == 200
    dash_data = dash_res.get_json()

    # Find events related to our file
    events_for_file = [log["event"] for log in dash_data["logs"] if log["file_id"] == file_id]
    print(f"  -> Recorded events for file {file_id}: {events_for_file}")
    assert "upload" in events_for_file, "Upload event missing from timeline"
    assert "view" in events_for_file, "View event missing from timeline"
    assert "download" in events_for_file, "Download event missing from timeline"
    assert "revoke" in events_for_file, "Revoke event missing from timeline"
    assert "failed_attempt" in events_for_file, "Failed attempt event missing from timeline"

    print("\n" + "=" * 70)
    print("ALL 9 STAGES OF THE WORKFLOW PASSED WITH 100% SUCCESS!")
    print("=" * 70)

if __name__ == "__main__":
    verify_full_system_workflow()
