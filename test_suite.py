import io
import os
import time
import base64
import unittest
from pathlib import Path
from app import app, connect, stored_path

# Import cryptography for full AES-256-GCM lifecycle verification
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class VaultXTestSuite(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_01_static_files(self):
        """Test all static CSS and JS routes return 200 OK."""
        static_urls = [
            "/static/css/style.css",
            "/static/js/encryption.js",
            "/static/js/upload.js",
            "/static/js/download.js",
            "/static/js/dashboard.js",
            "/static/js/proof.js",
            "/static/js/sharing.js",
        ]
        for url in static_urls:
            res = self.client.get(url)
            self.assertEqual(res.status_code, 200, f"Static URL {url} failed with {res.status_code}")
            res.close()

    def test_02_template_routes(self):
        """Test all frontend page routes render with 200 OK and include new security/UI elements without QR code."""
        pages = ["/", "/upload", "/dashboard", "/proof", "/f/dummyid123"]
        for page in pages:
            res = self.client.get(page)
            self.assertEqual(res.status_code, 200, f"Page {page} failed with {res.status_code}")
            self.assertIn(b"Vault", res.data)
            res.close()

        # Check Home Page has AES-256-GCM and upload progress bar
        home_res = self.client.get("/")
        self.assertIn(b"AES-256-GCM", home_res.data)
        self.assertIn(b"uploadProgressBar", home_res.data)
        self.assertIn(b"shareLinkInput", home_res.data)
        home_res.close()

        # Check Upload Studio has drag-and-drop and progress bar
        upload_res = self.client.get("/upload")
        self.assertIn(b"upload-dropzone", upload_res.data)
        self.assertIn(b"uploadProgressBar", upload_res.data)
        self.assertIn(b"shareLinkInput", upload_res.data)
        upload_res.close()

        # Check Download Page has live countdown and security section
        dl_page_res = self.client.get("/f/test12345")
        self.assertIn(b"timerDays", dl_page_res.data)
        self.assertIn(b"timerHours", dl_page_res.data)
        self.assertIn(b"timerMins", dl_page_res.data)
        self.assertIn(b"timerSecs", dl_page_res.data)
        self.assertIn(b"AES-256-GCM Cryptographic Verification", dl_page_res.data)
        dl_page_res.close()

        # Check Dashboard has Smart Security Score, Revoke Modal, Threat Alerts, and NO QR modal
        dash_page_res = self.client.get("/dashboard")
        self.assertIn(b"dashboard-search", dash_page_res.data)
        self.assertIn(b"security-score-section", dash_page_res.data)
        self.assertIn(b"security-score-val", dash_page_res.data)
        self.assertIn(b"threatAlertsSection", dash_page_res.data)
        self.assertIn(b"revokeModal", dash_page_res.data)
        self.assertIn(b"system-health-badge", dash_page_res.data)
        # Ensure QR modal was completely removed from the user interface
        self.assertNotIn(b"qrModal", dash_page_res.data)
        dash_page_res.close()

    def test_03_database_health(self):
        """Test database connection and health check endpoint."""
        res = self.client.get("/api/health")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "healthy")
        self.assertEqual(data["database"], "connected")
        self.assertIn("file_count", data)
        res.close()

    def test_04_full_lifecycle(self):
        """Test upload -> metadata -> download -> logs -> blind proof -> revocation."""
        # 1. Upload
        iv_bytes = b"123456789012"
        iv_b64 = base64.b64encode(iv_bytes).decode("utf-8")
        raw_payload = b"SampleEncryptedCiphertextWithAuthTag12345"

        upload_res = self.client.post("/api/upload", data={
            "file": (io.BytesIO(raw_payload), "encrypted.bin"),
            "iv": iv_b64,
            "original_filename": "secret_doc.pdf",
            "mime_type": "application/pdf",
            "expiry": "1d"
        })
        self.assertEqual(upload_res.status_code, 201)
        upload_data = upload_res.get_json()
        self.assertTrue(upload_data["success"])
        file_id = upload_data["id"]
        self.assertTrue(len(file_id) > 10)
        upload_res.close()

        # 2. Check stored file on disk
        path = stored_path(file_id)
        self.assertTrue(path.exists(), "Stored encrypted file must exist on disk")
        self.assertEqual(path.read_bytes(), raw_payload)

        # 3. Retrieve metadata (logs view event)
        meta_res = self.client.get(f"/api/files/{file_id}/meta")
        self.assertEqual(meta_res.status_code, 200)
        meta_data = meta_res.get_json()
        self.assertEqual(meta_data["filename"], "secret_doc.pdf")
        self.assertEqual(meta_data["mime_type"], "application/pdf")
        self.assertEqual(meta_data["iv"], iv_b64)
        self.assertEqual(meta_data["size"], len(raw_payload))
        meta_res.close()

        # 4. Download file (logs download event)
        dl_res = self.client.get(f"/api/files/{file_id}")
        self.assertEqual(dl_res.status_code, 200)
        self.assertEqual(dl_res.data, raw_payload)
        dl_res.close()

        # 5. Dashboard data check
        dash_res = self.client.get("/api/files")
        self.assertEqual(dash_res.status_code, 200)
        dash_data = dash_res.get_json()
        self.assertGreaterEqual(dash_data["stats"]["total_files"], 1)
        self.assertGreaterEqual(dash_data["stats"]["total_downloads"], 1)

        # Verify access logs contain upload, view, and download
        events = [log["event"] for log in dash_data["logs"] if log["file_id"] == file_id]
        self.assertIn("upload", events)
        self.assertIn("view", events)
        self.assertIn("download", events)
        dash_res.close()

        # 6. Server blind proof check
        proof_res = self.client.get("/api/blind-proof")
        self.assertEqual(proof_res.status_code, 200)
        proof_items = proof_res.get_json()
        matching_proof = next((item for item in proof_items if item["id"] == file_id), None)
        self.assertIsNotNone(matching_proof)
        self.assertEqual(matching_proof["stored_name"], f"{file_id}.bin")
        self.assertFalse(matching_proof["has_key"])
        self.assertEqual(matching_proof["hex_preview"], raw_payload[:32].hex())
        proof_res.close()

        # 7. Revoke / Delete
        del_res = self.client.delete(f"/api/files/{file_id}")
        self.assertEqual(del_res.status_code, 200)
        self.assertFalse(path.exists(), "Stored file should be deleted on revocation")
        del_res.close()

        # 8. Post-revocation checks
        m_check = self.client.get(f"/api/files/{file_id}/meta")
        self.assertEqual(m_check.status_code, 404)
        m_check.close()

        d_check = self.client.get(f"/api/files/{file_id}")
        self.assertEqual(d_check.status_code, 404)
        d_check.close()

    def test_05_validation_errors(self):
        """Test API validation handles malformed requests gracefully."""
        # Missing file
        res = self.client.post("/api/upload", data={"iv": "MTIzNDU2Nzg5MDEy"})
        self.assertEqual(res.status_code, 400)
        res.close()

        # Missing IV
        res = self.client.post("/api/upload", data={"file": (io.BytesIO(b"A"*20), "f.bin")})
        self.assertEqual(res.status_code, 400)
        res.close()

        # Invalid IV length
        short_iv = base64.b64encode(b"short").decode("utf-8")
        res = self.client.post("/api/upload", data={
            "file": (io.BytesIO(b"A"*20), "f.bin"),
            "iv": short_iv
        })
        self.assertEqual(res.status_code, 400)
        res.close()

        # Invalid expiry
        iv_b64 = base64.b64encode(b"123456789012").decode("utf-8")
        res = self.client.post("/api/upload", data={
            "file": (io.BytesIO(b"A"*20), "f.bin"),
            "iv": iv_b64,
            "expiry": "999years"
        })
        self.assertEqual(res.status_code, 400)
        res.close()

    def test_06_expiry_handling(self):
        """Test expired files return 410 Gone."""
        iv_b64 = base64.b64encode(b"123456789012").decode("utf-8")
        upload_res = self.client.post("/api/upload", data={
            "file": (io.BytesIO(b"A"*32), "test.bin"),
            "iv": iv_b64,
            "original_filename": "test.txt",
            "expiry": "1h"
        })
        file_id = upload_res.get_json()["id"]
        upload_res.close()

        # Manually backdate expires_at in DB
        with connect() as conn:
            conn.execute("UPDATE vault_files SET expires_at = ? WHERE id = ?", (int(time.time()) - 100, file_id))

        meta_res = self.client.get(f"/api/files/{file_id}/meta")
        self.assertEqual(meta_res.status_code, 410)
        meta_res.close()

        dl_res = self.client.get(f"/api/files/{file_id}")
        self.assertEqual(dl_res.status_code, 410)
        dl_res.close()

        # Clean up
        c_res = self.client.delete(f"/api/files/{file_id}")
        c_res.close()

    def test_07_real_aes256_gcm_cryptographic_workflow(self):
        """
        Comprehensive test:
        1. Encrypt plaintext using genuine 256-bit AES-GCM (same as WebCrypto).
        2. Upload to VaultX.
        3. Verify zero keys stored in server database.
        4. Download encrypted ciphertext from VaultX.
        5. Decrypt using the client key and verify 100% bit-for-bit plaintext match.
        6. Verify tampering triggers AESGCM authentication failure.
        """
        # Original plaintext
        original_plaintext = b"CONFIDENTIAL HACKATHON FINANCIAL STATEMENT - VAULTX ZERO-KNOWLEDGE PROOF 2026"

        # 1. Generate 256-bit AES key and 96-bit (12-byte) IV
        key = AESGCM.generate_key(bit_length=256)
        iv = os.urandom(12)
        aesgcm = AESGCM(key)

        # Encrypt (produces ciphertext + 16-byte tag, exactly matching WebCrypto SubtleCrypto)
        ciphertext = aesgcm.encrypt(iv, original_plaintext, None)

        iv_b64 = base64.b64encode(iv).decode("utf-8")
        key_b64 = base64.b64encode(key).decode("utf-8")

        # 2. Upload to VaultX
        upload_res = self.client.post("/api/upload", data={
            "file": (io.BytesIO(ciphertext), "encrypted.bin"),
            "iv": iv_b64,
            "original_filename": "financial_statement.pdf",
            "mime_type": "application/pdf",
            "expiry": "1d"
        })
        self.assertEqual(upload_res.status_code, 201)
        upload_data = upload_res.get_json()
        file_id = upload_data["id"]
        upload_res.close()

        # 3. VERIFY ZERO KEYS STORED IN SERVER DATABASE
        with connect() as conn:
            row = conn.execute("SELECT * FROM vault_files WHERE id = ?", (file_id,)).fetchone()
            self.assertIsNotNone(row)
            # The database stores filename, mime_type, iv, size, created_at, expires_at, downloads
            # The database column names:
            col_names = [d[0] for d in conn.execute("SELECT * FROM vault_files LIMIT 1").description]
            self.assertNotIn("key", col_names, "Database schema MUST NOT have a key column")
            self.assertNotIn("password", col_names)
            # Verify the key string never appears in any string representation of the DB row
            self.assertNotIn(key_b64, str(dict(row)), "Encryption key MUST NOT be stored in database")

        # 4. Download encrypted payload
        dl_res = self.client.get(f"/api/files/{file_id}")
        self.assertEqual(dl_res.status_code, 200)
        downloaded_ciphertext = dl_res.data
        dl_res.close()

        # 5. Client-Side Decryption
        decrypted_plaintext = aesgcm.decrypt(iv, downloaded_ciphertext, None)
        self.assertEqual(decrypted_plaintext, original_plaintext, "Decrypted data must match original plaintext exactly!")

        # 6. Tamper verification: if even 1 byte of ciphertext is altered, GCM tag verification MUST fail
        tampered_ciphertext = bytearray(downloaded_ciphertext)
        tampered_ciphertext[0] ^= 0xFF  # Flip bits of first byte
        with self.assertRaises(Exception):
            aesgcm.decrypt(iv, bytes(tampered_ciphertext), None)

        # Clean up
        self.client.delete(f"/api/files/{file_id}")

    def test_08_smart_security_score_calculation(self):
        """Test Smart Security Score calculation verifies actual active security features."""
        res = self.client.get("/api/security-score")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()

        self.assertIn("total_score", data)
        self.assertIn("max_score", data)
        self.assertIn("grade", data)
        self.assertIn("status", data)
        self.assertIn("checks", data)
        self.assertEqual(data["max_score"], 100)
        self.assertGreaterEqual(data["total_score"], 70)

        # Verify all 5 genuine security checks are present and evaluated
        check_ids = [c["id"] for c in data["checks"]]
        self.assertIn("cipher_suite", check_ids)
        self.assertIn("zero_knowledge", check_ids)
        self.assertIn("ephemeral_ttl", check_ids)
        self.assertIn("emergency_revoke", check_ids)
        self.assertIn("threat_defense", check_ids)

        for check in data["checks"]:
            self.assertIn("score", check)
            self.assertIn("max", check)
            self.assertIn("passed", check)
            self.assertIn("description", check)
            self.assertGreater(check["max"], 0)
        res.close()

    def test_09_emergency_revocation_workflow(self):
        """
        Test Emergency Revocation feature:
        1. Upload a file.
        2. Verify file exists on disk.
        3. Trigger emergency revoke via POST /api/files/<id>/revoke.
        4. Verify ciphertext is immediately purged from disk.
        5. Verify subsequent meta request returns 404 with revoked=True.
        6. Verify download request is rejected.
        7. Verify revocation is recorded in access_logs.
        """
        iv_b64 = base64.b64encode(b"123456789012").decode("utf-8")
        payload = b"TopSecretRevocationTestCiphertext12345"

        upload_res = self.client.post("/api/upload", data={
            "file": (io.BytesIO(payload), "file.bin"),
            "iv": iv_b64,
            "original_filename": "emergency_doc.pdf",
            "mime_type": "application/pdf",
            "expiry": "1d"
        })
        self.assertEqual(upload_res.status_code, 201)
        file_id = upload_res.get_json()["id"]
        upload_res.close()

        # Stored file must exist initially
        fpath = stored_path(file_id)
        self.assertTrue(fpath.exists())

        # Execute Emergency Revocation
        revoke_res = self.client.post(f"/api/files/{file_id}/revoke")
        self.assertEqual(revoke_res.status_code, 200)
        revoke_data = revoke_res.get_json()
        self.assertTrue(revoke_data["success"])
        revoke_res.close()

        # 1. Physical ciphertext must be erased from disk
        self.assertFalse(fpath.exists(), "Ciphertext file must be purged from disk immediately on revoke")

        # 2. Subsequent meta request must return 404 with revoked indication
        meta_res = self.client.get(f"/api/files/{file_id}/meta")
        self.assertEqual(meta_res.status_code, 404)
        meta_data = meta_res.get_json()
        self.assertTrue(meta_data.get("revoked", False))
        self.assertIn("revoked", meta_data.get("error", "").lower())
        meta_res.close()

        # 3. Subsequent download request must be rejected
        dl_res = self.client.get(f"/api/files/{file_id}")
        self.assertEqual(dl_res.status_code, 404)
        dl_res.close()

        # 4. Check access_logs records revoke event
        with connect() as conn:
            revoke_log = conn.execute(
                "SELECT * FROM access_logs WHERE file_id = ? AND event = 'revoke'",
                (file_id,)
            ).fetchone()
            self.assertIsNotNone(revoke_log, "Revocation event must be logged in audit trail")

    def test_10_suspicious_activity_alerts(self):
        """
        Test Suspicious Activity Alerts feature:
        Repeated failed access attempts (>= 3) on a file ID triggers a warning alert.
        """
        fake_id = "target_probe_file_999"
        # Simulate 4 failed attempts on this ID
        for _ in range(4):
            res = self.client.get(f"/api/files/{fake_id}/meta")
            self.assertEqual(res.status_code, 404)
            res.close()

        # Check /api/security/alerts returns suspicious activity warning
        alerts_res = self.client.get("/api/security/alerts")
        self.assertEqual(alerts_res.status_code, 200)
        alerts_data = alerts_res.get_json()

        self.assertGreaterEqual(alerts_data["count"], 1)
        found_alert = next((a for a in alerts_data["alerts"] if a["file_id"] == fake_id), None)
        self.assertIsNotNone(found_alert, "Repeated failed attempts must trigger an alert")
        self.assertGreaterEqual(found_alert["fail_count"], 3)
        self.assertIn(found_alert["severity"], ["high", "critical"])
        alerts_res.close()

    def test_11_activity_timeline_events(self):
        """Test Activity Timeline records all lifecycle events with filenames."""
        dash_res = self.client.get("/api/files")
        self.assertEqual(dash_res.status_code, 200)
        dash_data = dash_res.get_json()
        self.assertIn("logs", dash_data)
        logs = dash_data["logs"]
        self.assertGreater(len(logs), 0)

        # Verify logs structure
        for log in logs[:10]:
            self.assertIn("id", log)
            self.assertIn("file_id", log)
            self.assertIn("event", log)
            self.assertIn("created_at", log)
            self.assertIn("filename", log)
        dash_res.close()

    def test_12_expiry_countdown_calculation(self):
        """Test remaining_seconds calculation in API metadata."""
        iv_b64 = base64.b64encode(b"123456789012").decode("utf-8")
        upload_res = self.client.post("/api/upload", data={
            "file": (io.BytesIO(b"A"*32), "file.bin"),
            "iv": iv_b64,
            "original_filename": "countdown_doc.txt",
            "mime_type": "text/plain",
            "expiry": "1h"
        })
        file_id = upload_res.get_json()["id"]
        upload_res.close()

        meta_res = self.client.get(f"/api/files/{file_id}/meta")
        self.assertEqual(meta_res.status_code, 200)
        meta_data = meta_res.get_json()
        self.assertIn("remaining_seconds", meta_data)
        self.assertGreater(meta_data["remaining_seconds"], 0)
        self.assertLessEqual(meta_data["remaining_seconds"], 3600)
        meta_res.close()

        # Clean up
        self.client.delete(f"/api/files/{file_id}")

if __name__ == "__main__":
    unittest.main()
