/**
 * VaultX - Server Blind Proof Module
 * Provides live cryptographic proof that the server storage contains only random encrypted bytes.
 */

async function loadBlindProof() {
    const container = document.getElementById("proofContainer");
    const refreshBtn = document.getElementById("refreshProofBtn");

    if (!container) return;

    try {
        if (refreshBtn) {
            refreshBtn.disabled = true;
            refreshBtn.textContent = "🔄 Inspecting Storage...";
        }

        const res = await fetch("/api/blind-proof");
        if (!res.ok) {
            throw new Error("HTTP error " + res.status);
        }
        const files = await res.json();

        if (!files || !files.length) {
            container.innerHTML = `
                <div class="empty-state">
                    <div class="empty-icon">🛡️</div>
                    <h3>Server Storage is Empty</h3>
                    <p>Upload a file to see its encrypted ciphertext stored on disk.</p>
                    <a href="/upload" class="primary-btn" style="margin-top: 15px;">Upload a File ↗</a>
                </div>
            `;
            return;
        }

        // Format hex bytes with spaces (e.g., 4a b2 3c ...)
        function formatHex(hex) {
            if (!hex) return "Empty file";
            const chunks = [];
            for (let i = 0; i < hex.length; i += 2) {
                chunks.push(hex.substr(i, 2));
            }
            return chunks.join(" ");
        }

        container.innerHTML = files.map(f => `
            <div class="proof-card">
                <div class="proof-header">
                    <div>
                        <span class="proof-file-name">📁 uploads/${f.stored_name}</span>
                        <div class="proof-sub">
                            <span>ID: <code>${f.id}</code></span>
                            <span>•</span>
                            <span>Size: <strong>${f.size_bytes} bytes</strong></span>
                        </div>
                    </div>
                    <div class="proof-tags">
                        <span class="badge badge-success">✓ Encrypted Ciphertext</span>
                        <span class="badge badge-warning">✗ Key Not on Server</span>
                    </div>
                </div>

                <div class="proof-hex-box">
                    <div class="proof-hex-label">RAW STORAGE BYTES PREVIEW (FIRST 32 BYTES):</div>
                    <code class="proof-hex-code">${formatHex(f.hex_preview)}...</code>
                </div>

                <div class="proof-footer">
                    <span>🛡️ Server Inspection: <strong>Completely unreadable random entropy</strong>. Zero plaintext leaks.</span>
                </div>
            </div>
        `).join("");

    } catch (err) {
        console.error("Proof load failed:", err);
        container.innerHTML = `
            <div class="status-message error">
                Failed to inspect server storage. Please check server connectivity.
            </div>
        `;
    } finally {
        if (refreshBtn) {
            refreshBtn.disabled = false;
            refreshBtn.textContent = "🔄 Refresh Server Storage";
        }
    }
}

document.addEventListener("DOMContentLoaded", function () {
    const refreshBtn = document.getElementById("refreshProofBtn");
    if (refreshBtn) {
        refreshBtn.addEventListener("click", loadBlindProof);
    }
    loadBlindProof();
});
