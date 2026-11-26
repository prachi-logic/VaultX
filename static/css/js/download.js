/**
 * VaultX - Download and Decrypt Module
 * Fetches encrypted payload from server, decrypts client-side using the URL fragment key,
 * and allows instant in-browser viewing or downloading.
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
    const fileExpiryEl = document.getElementById("downloadFileExpiry");
    const fileDownloadsEl = document.getElementById("downloadFileDownloads");

    const downloadBtn = document.getElementById("downloadBtn");
    const previewBtn = document.getElementById("previewBtn");
    const statusBox = document.getElementById("downloadStatus");
    const previewContainer = document.getElementById("previewContainer");
    const previewContent = document.getElementById("previewContent");

    let cachedMetadata = null;
    let decryptedBlobUrl = null;
    let decryptedDataArray = null;

    function formatBytes(bytes) {
        if (!bytes || bytes === 0) return "0 Bytes";
        const k = 1024;
        const sizes = ["Bytes", "KB", "MB", "GB"];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
    }

    function formatTime(unixSeconds) {
        if (!unixSeconds) return "N/A";
        return new Date(unixSeconds * 1000).toLocaleString();
    }

    function setStatus(msg, type = "info") {
        if (!statusBox) return;
        statusBox.textContent = msg;
        statusBox.className = "status-message " + type;
        statusBox.style.display = "block";
    }

    function showError(msg) {
        if (loadingCard) loadingCard.style.display = "none";
        if (fileCard) fileCard.style.display = "none";
        if (errorCard) errorCard.style.display = "block";
        if (errorMessage) errorMessage.textContent = msg;
    }

    // Check key in hash
    if (!keyText) {
        showError("Decryption key is missing from the URL. Please verify you have the complete link including the '#' fragment.");
        return;
    }

    // 1. Fetch File Metadata
    try {
        const metaRes = await fetch("/api/files/" + encodeURIComponent(fileId) + "/meta");
        const meta = await metaRes.json();

        if (metaRes.status === 404) {
            showError("File not found. It may have been revoked or deleted by the owner.");
            return;
        }

        if (metaRes.status === 410) {
            showError("This secure link has expired and is no longer available.");
            return;
        }

        if (!metaRes.ok) {
            showError(meta.error || "Failed to retrieve file details.");
            return;
        }

        cachedMetadata = meta;

        if (fileNameEl) fileNameEl.textContent = meta.filename;
        if (fileSizeEl) fileSizeEl.textContent = formatBytes(meta.size);
        if (fileTypeEl) fileTypeEl.textContent = meta.mime_type || "application/octet-stream";
        if (fileExpiryEl) fileExpiryEl.textContent = formatTime(meta.expires_at);
        if (fileDownloadsEl) fileDownloadsEl.textContent = (meta.downloads || 0) + " downloads";

        if (loadingCard) loadingCard.style.display = "none";
        if (fileCard) fileCard.style.display = "block";

    } catch (err) {
        console.error("Meta retrieval error:", err);
        showError("Could not connect to server. Please check your network connection.");
        return;
    }

    // Helper: Decrypt payload
    async function getDecryptedBlob() {
        if (decryptedBlobUrl && decryptedDataArray) {
            return { blobUrl: decryptedBlobUrl, data: decryptedDataArray };
        }

        if (!window.VaultXEncryption) {
            throw new Error("Encryption module not available.");
        }

        setStatus("Fetching encrypted payload from vault...", "info");
        const fileRes = await fetch("/api/files/" + encodeURIComponent(fileId));
        if (!fileRes.ok) {
            const errData = await fileRes.json().catch(() => ({}));
            throw new Error(errData.error || "Failed to download encrypted data.");
        }

        const encryptedData = await fileRes.arrayBuffer();

        setStatus("Decrypting with AES-256-GCM in browser memory...", "info");
        const decrypted = await window.VaultXEncryption.decryptFile(
            encryptedData,
            cachedMetadata.iv,
            keyText
        );

        decryptedDataArray = decrypted;
        const blob = new Blob([decrypted], { type: cachedMetadata.mime_type || "application/octet-stream" });
        decryptedBlobUrl = URL.createObjectURL(blob);

        return { blobUrl: decryptedBlobUrl, data: decryptedDataArray };
    }

    // 2. Download Button
    if (downloadBtn) {
        downloadBtn.addEventListener("click", async function () {
            try {
                downloadBtn.disabled = true;
                const { blobUrl } = await getDecryptedBlob();

                setStatus("Decryption complete! Triggering file download...", "success");

                const a = document.createElement("a");
                a.href = blobUrl;
                a.download = cachedMetadata.filename || "decrypted-file";
                document.body.appendChild(a);
                a.click();
                a.remove();

                setStatus(`Successfully decrypted and downloaded "${cachedMetadata.filename}".`, "success");

                // Update download counter in UI
                if (fileDownloadsEl && cachedMetadata.downloads !== undefined) {
                    cachedMetadata.downloads += 1;
                    fileDownloadsEl.textContent = cachedMetadata.downloads + " downloads";
                }

            } catch (err) {
                console.error("Download Error:", err);
                setStatus("Decryption failed: " + (err.message || "Invalid key or corrupted data."), "error");
            } finally {
                downloadBtn.disabled = false;
            }
        });
    }

    // 3. View / Preview Button
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
                if (mime.startsWith("image/") || /\.(png|jpe?g|gif|webp|svg|bmp)$/i.test(fname)) {
                    const img = document.createElement("img");
                    img.src = blobUrl;
                    img.alt = cachedMetadata.filename;
                    img.className = "preview-image";
                    previewContent.appendChild(img);
                    setStatus("Image preview loaded.", "success");
                }
                // Text / Code / JSON / Markdown
                else if (
                    mime.startsWith("text/") ||
                    mime === "application/json" ||
                    mime === "application/javascript" ||
                    /\.(txt|json|md|py|js|html|css|csv|log|sh|xml|yaml|yml)$/i.test(fname)
                ) {
                    const text = new TextDecoder().decode(data);
                    const pre = document.createElement("pre");
                    pre.className = "preview-code";
                    pre.textContent = text.slice(0, 100000); // Up to 100KB preview
                    if (text.length > 100000) {
                        const note = document.createElement("p");
                        note.className = "preview-note";
                        note.textContent = "Showing first 100 KB of text file. Download for full content.";
                        previewContent.appendChild(note);
                    }
                    previewContent.appendChild(pre);
                    setStatus("Text preview loaded.", "success");
                }
                // Audio
                else if (mime.startsWith("audio/") || /\.(mp3|wav|ogg|m4a|aac)$/i.test(fname)) {
                    const audio = document.createElement("audio");
                    audio.controls = true;
                    audio.src = blobUrl;
                    audio.className = "preview-media";
                    previewContent.appendChild(audio);
                    setStatus("Audio player ready.", "success");
                }
                // Video
                else if (mime.startsWith("video/") || /\.(mp4|webm|ogv|mov)$/i.test(fname)) {
                    const video = document.createElement("video");
                    video.controls = true;
                    video.src = blobUrl;
                    video.className = "preview-media";
                    previewContent.appendChild(video);
                    setStatus("Video player ready.", "success");
                }
                // PDF
                else if (mime === "application/pdf" || fname.endsWith(".pdf")) {
                    const iframe = document.createElement("iframe");
                    iframe.src = blobUrl;
                    iframe.className = "preview-frame";
                    iframe.title = cachedMetadata.filename;
                    previewContent.appendChild(iframe);
                    setStatus("PDF preview loaded.", "success");
                }
                // Other Binary
                else {
                    const msg = document.createElement("div");
                    msg.className = "preview-unsupported";
                    msg.innerHTML = `
                        <p>In-browser preview is not available for <code>${cachedMetadata.mime_type}</code> files.</p>
                        <p>Click <strong>Decrypt & Download</strong> above to save and view it on your device.</p>
                    `;
                    previewContent.appendChild(msg);
                    setStatus("Preview not supported for this file type.", "info");
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
