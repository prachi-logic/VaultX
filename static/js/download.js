/**
 * VaultX - Download and Decrypt Module
 * Fetches encrypted ciphertext, decrypts client-side using WebCrypto AES-256-GCM,
 * runs a real-time live expiry countdown, and supports in-browser preview or download.
 */

document.addEventListener("DOMContentLoaded", async function () {
    const fileId = window.location.pathname.split("/").filter(Boolean).pop();
    const hash = window.location.hash;
    const keyText = hash ? hash.substring(1) : "";

    const loadingCard = document.getElementById("loadingCard");
    const fileCard = document.getElementById("fileCard");
    const errorCard = document.getElementById("errorCard");
    const errorMessage = document.getElementById("errorMessage");

    const fileNameEl = document.getElementById("downloadFileName");
    const fileSizeEl = document.getElementById("downloadFileSize");
    const fileTypeEl = document.getElementById("downloadFileType");
    const fileDownloadsEl = document.getElementById("downloadFileDownloads");
    const fileIconEl = document.getElementById("downloadFileIcon");

    // Countdown elements
    const countdownDaysEl = document.getElementById("timerDays");
    const countdownHoursEl = document.getElementById("timerHours");
    const countdownMinsEl = document.getElementById("timerMins");
    const countdownSecsEl = document.getElementById("timerSecs");
    const countdownBarEl = document.getElementById("timerProgressBar");
    const countdownBadgeEl = document.getElementById("countdownBadge");

    const downloadBtn = document.getElementById("downloadBtn");
    const previewBtn = document.getElementById("previewBtn");
    const statusBox = document.getElementById("downloadStatus");
    const previewContainer = document.getElementById("previewContainer");
    const previewContent = document.getElementById("previewContent");

    let cachedMetadata = null;
    let decryptedBlobUrl = null;
    let decryptedDataArray = null;
    let countdownInterval = null;

    function formatBytes(bytes) {
        if (!bytes || bytes === 0) return "0 Bytes";
        const k = 1024;
        const sizes = ["Bytes", "KB", "MB", "GB"];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
    }

    function getFileIcon(filename) {
        const ext = (filename.split(".").pop() || "").toLowerCase();
        if (["png", "jpg", "jpeg", "gif", "webp", "svg", "bmp"].includes(ext)) return "🖼️";
        if (["mp4", "webm", "mkv", "mov", "avi"].includes(ext)) return "🎬";
        if (["mp3", "wav", "ogg", "m4a", "flac"].includes(ext)) return "🎵";
        if (["pdf"].includes(ext)) return "📕";
        if (["zip", "tar", "gz", "7z", "rar"].includes(ext)) return "📦";
        if (["js", "py", "html", "css", "json", "ts", "cpp", "c", "java", "sql"].includes(ext)) return "💻";
        if (["txt", "md", "csv", "log"].includes(ext)) return "📝";
        return "📦";
    }

    function setStatus(msg, type = "info") {
        if (!statusBox) return;
        statusBox.textContent = msg;
        statusBox.className = "status-message " + type;
        statusBox.style.display = "block";
    }

    function showError(msg) {
        if (countdownInterval) {
            clearInterval(countdownInterval);
            countdownInterval = null;
        }
        if (loadingCard) loadingCard.style.display = "none";
        if (fileCard) fileCard.style.display = "none";
        if (errorCard) errorCard.style.display = "block";
        if (errorMessage) errorMessage.textContent = msg;
    }

    // Start Live Link Expiry Countdown
    function startCountdown(createdAt, expiresAt) {
        if (!expiresAt) return;
        const totalDuration = Math.max(1, expiresAt - createdAt);

        function tick() {
            const now = Math.floor(Date.now() / 1000);
            const remaining = expiresAt - now;

            if (remaining <= 0) {
                if (countdownDaysEl) countdownDaysEl.textContent = "00";
                if (countdownHoursEl) countdownHoursEl.textContent = "00";
                if (countdownMinsEl) countdownMinsEl.textContent = "00";
                if (countdownSecsEl) countdownSecsEl.textContent = "00";
                if (countdownBarEl) countdownBarEl.style.width = "0%";
                if (countdownBadgeEl) {
                    countdownBadgeEl.innerHTML = `<span class="badge badge-expired">🚨 LINK EXPIRED</span>`;
                }

                if (downloadBtn) downloadBtn.disabled = true;
                if (previewBtn) previewBtn.disabled = true;
                setStatus("This secure link has expired. Decryption is no longer possible.", "error");

                clearInterval(countdownInterval);
                return;
            }

            const days = Math.floor(remaining / 86400);
            const hours = Math.floor((remaining % 86400) / 3600);
            const mins = Math.floor((remaining % 3600) / 60);
            const secs = remaining % 60;

            const pad = n => String(n).padStart(2, "0");

            if (countdownDaysEl) countdownDaysEl.textContent = pad(days);
            if (countdownHoursEl) countdownHoursEl.textContent = pad(hours);
            if (countdownMinsEl) countdownMinsEl.textContent = pad(mins);
            if (countdownSecsEl) countdownSecsEl.textContent = pad(secs);

            // Remaining percentage for progress bar
            const percentRemaining = Math.max(0, Math.min(100, (remaining / totalDuration) * 100));
            if (countdownBarEl) {
                countdownBarEl.style.width = percentRemaining + "%";
                if (percentRemaining < 15) {
                    countdownBarEl.style.background = "var(--danger)";
                } else if (percentRemaining < 35) {
                    countdownBarEl.style.background = "var(--amber)";
                } else {
                    countdownBarEl.style.background = "var(--accent-gradient)";
                }
            }

            if (countdownBadgeEl) {
                countdownBadgeEl.innerHTML = `
                    <span class="live-dot-pulse"></span>
                    <span>Self-destructs in <strong>${days > 0 ? days + 'd ' : ''}${pad(hours)}:${pad(mins)}:${pad(secs)}</strong></span>
                `;
            }
        }

        tick();
        countdownInterval = setInterval(tick, 1000);
    }

    // Verify presence of key in URL hash fragment
    if (!keyText) {
        showError("The secret decryption key is missing from this link. VaultX links require the '#<key>' fragment to decrypt files locally in your browser.");
        return;
    }

    // 1. Fetch File Metadata
    try {
        const metaRes = await fetch("/api/files/" + encodeURIComponent(fileId) + "/meta");
        const meta = await metaRes.json();

        if (metaRes.status === 404) {
            if (meta.revoked) {
                showError("🚨 ACCESS REVOKED: This file was permanently revoked by the owner. The ciphertext has been purged from the server and the sharing link has been permanently deactivated.");
            } else {
                showError("File not found. It may have been revoked or permanently deleted by the sender.");
            }
            return;
        }

        if (metaRes.status === 410) {
            showError("This secure link has expired and the file has automatically self-destructed.");
            return;
        }

        if (!metaRes.ok) {
            showError(meta.error || "Failed to retrieve file metadata from vault.");
            return;
        }

        cachedMetadata = meta;

        if (fileNameEl) fileNameEl.textContent = meta.filename;
        if (fileSizeEl) fileSizeEl.textContent = formatBytes(meta.size);
        if (fileTypeEl) fileTypeEl.textContent = meta.mime_type || "application/octet-stream";
        if (fileDownloadsEl) fileDownloadsEl.textContent = (meta.downloads || 0) + " downloads";
        if (fileIconEl) fileIconEl.textContent = getFileIcon(meta.filename);

        // Start countdown timer
        startCountdown(meta.created_at, meta.expires_at);

        if (loadingCard) loadingCard.style.display = "none";
        if (fileCard) fileCard.style.display = "block";

    } catch (err) {
        console.error("Meta retrieval error:", err);
        showError("Unable to reach the VaultX server. Please verify your connection.");
        return;
    }

    // Helper: Decrypt payload locally
    async function getDecryptedBlob() {
        if (decryptedBlobUrl && decryptedDataArray) {
            return { blobUrl: decryptedBlobUrl, data: decryptedDataArray };
        }

        if (!window.VaultXEncryption) {
            throw new Error("VaultX encryption engine not available.");
        }

        setStatus("1/3 Fetching encrypted binary payload from server-blind vault...", "info");
        const fileRes = await fetch("/api/files/" + encodeURIComponent(fileId));
        if (!fileRes.ok) {
            const errData = await fileRes.json().catch(() => ({}));
            throw new Error(errData.error || "Failed to download encrypted data (status " + fileRes.status + ").");
        }

        const encryptedData = await fileRes.arrayBuffer();

        setStatus("2/3 Reconstructing 256-bit AES key & verifying GCM integrity tag...", "info");
        const decrypted = await window.VaultXEncryption.decryptFile(
            encryptedData,
            cachedMetadata.iv,
            keyText
        );

        setStatus("3/3 Decryption successful! File verified in browser RAM.", "success");
        decryptedDataArray = decrypted;
        const blob = new Blob([decrypted], { type: cachedMetadata.mime_type || "application/octet-stream" });
        decryptedBlobUrl = URL.createObjectURL(blob);

        return { blobUrl: decryptedBlobUrl, data: decryptedDataArray };
    }

    // 2. Download Button Handler
    if (downloadBtn) {
        downloadBtn.addEventListener("click", async function () {
            try {
                downloadBtn.disabled = true;
                const { blobUrl } = await getDecryptedBlob();

                setStatus("Decryption complete! Triggering browser download...", "success");

                const a = document.createElement("a");
                a.href = blobUrl;
                a.download = cachedMetadata.filename || "decrypted-file";
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);

                if (window.VaultXSharing) {
                    window.VaultXSharing.showToast(`Decrypted & downloaded "${cachedMetadata.filename}"`, "success");
                }

                // Update download counter
                if (fileDownloadsEl && cachedMetadata.downloads !== undefined) {
                    cachedMetadata.downloads += 1;
                    fileDownloadsEl.textContent = cachedMetadata.downloads + " downloads";
                }

            } catch (err) {
                console.error("Download Error:", err);
                try {
                    fetch("/api/files/" + encodeURIComponent(fileId) + "/report-failure", {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ reason: "Decryption tag failure or invalid key" })
                    }).catch(() => {});
                } catch (e) {}
                setStatus("Decryption failed: " + (err.message || "Invalid decryption key or corrupted ciphertext."), "error");
                if (window.VaultXSharing) {
                    window.VaultXSharing.showToast("Decryption failed: Check link key", "error");
                }
            } finally {
                downloadBtn.disabled = false;
            }
        });
    }

    // 3. View / Preview Button Handler
    if (previewBtn) {
        previewBtn.addEventListener("click", async function () {
            try {
                previewBtn.disabled = true;
                const { blobUrl, data } = await getDecryptedBlob();
                const mime = (cachedMetadata.mime_type || "").toLowerCase();
                const fname = (cachedMetadata.filename || "").toLowerCase();

                if (!previewContainer || !previewContent) return;

                previewContent.innerHTML = "";
                previewContainer.style.display = "block";

                // Images
                if (mime.startsWith("image/") || /\.(png|jpe?g|gif|webp|svg|bmp|ico)$/i.test(fname)) {
                    const img = document.createElement("img");
                    img.src = blobUrl;
                    img.alt = cachedMetadata.filename;
                    img.className = "preview-image";
                    previewContent.appendChild(img);
                    setStatus("Image preview decrypted and rendered.", "success");
                }
                // Text / Code / JSON / Markdown
                else if (
                    mime.startsWith("text/") ||
                    mime === "application/json" ||
                    mime === "application/javascript" ||
                    /\.(txt|json|md|py|js|html|css|csv|log|sh|xml|yaml|yml|sql|rs|go|java|c|cpp|h)$/i.test(fname)
                ) {
                    const text = new TextDecoder().decode(data);
                    const pre = document.createElement("pre");
                    pre.className = "preview-code";
                    pre.textContent = text.slice(0, 100000);
                    if (text.length > 100000) {
                        const note = document.createElement("p");
                        note.className = "preview-note";
                        note.textContent = "Showing first 100 KB of decrypted text. Download to see full content.";
                        previewContent.appendChild(note);
                    }
                    previewContent.appendChild(pre);
                    setStatus("Text file preview decrypted and loaded.", "success");
                }
                // Audio
                else if (mime.startsWith("audio/") || /\.(mp3|wav|ogg|m4a|aac|flac)$/i.test(fname)) {
                    const audio = document.createElement("audio");
                    audio.controls = true;
                    audio.src = blobUrl;
                    audio.className = "preview-media";
                    previewContent.appendChild(audio);
                    setStatus("Audio decrypted and ready to play.", "success");
                }
                // Video
                else if (mime.startsWith("video/") || /\.(mp4|webm|ogv|mov)$/i.test(fname)) {
                    const video = document.createElement("video");
                    video.controls = true;
                    video.src = blobUrl;
                    video.className = "preview-media";
                    previewContent.appendChild(video);
                    setStatus("Video decrypted and ready to play.", "success");
                }
                // PDF
                else if (mime === "application/pdf" || fname.endsWith(".pdf")) {
                    const iframe = document.createElement("iframe");
                    iframe.src = blobUrl;
                    iframe.className = "preview-frame";
                    iframe.title = cachedMetadata.filename;
                    previewContent.appendChild(iframe);
                    setStatus("PDF preview decrypted.", "success");
                }
                // Other Binary
                else {
                    const msg = document.createElement("div");
                    msg.className = "preview-unsupported";
                    msg.innerHTML = `
                        <p>In-browser preview is not supported for <code>${cachedMetadata.mime_type}</code>.</p>
                        <p>Click <strong>Decrypt & Download</strong> above to save and open it on your device.</p>
                    `;
                    previewContent.appendChild(msg);
                    setStatus("In-browser preview not supported for this format. Please download.", "info");
                }

                previewContainer.scrollIntoView({ behavior: "smooth", block: "nearest" });

            } catch (err) {
                console.error("Preview Error:", err);
                setStatus("Decryption preview failed: " + (err.message || "Invalid key."), "error");
            } finally {
                previewBtn.disabled = false;
            }
        });
    }
});
