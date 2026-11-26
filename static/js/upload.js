/**
 * VaultX - Upload Module
 * Client-side AES-256-GCM file encryption, multi-stage animated progress,
 * zero-knowledge QR code generation, and live expiry countdown.
 */

document.addEventListener("DOMContentLoaded", function () {
    const fileInput = document.getElementById("fileInput");
    const dropZone = document.getElementById("dropZone") || document.querySelector(".upload-dropzone");
    const uploadBtn = document.getElementById("uploadBtn");
    const fileInfo = document.getElementById("fileInfo");
    const fileNameEl = document.getElementById("fileName");
    const fileSizeEl = document.getElementById("fileSize");
    const fileTypeEl = document.getElementById("fileType");
    const fileIconEl = document.getElementById("fileIcon");
    const removeFileBtn = document.getElementById("removeFileBtn");

    const statusBox = document.getElementById("status");
    const progressContainer = document.getElementById("uploadProgressBar");
    const progressFill = document.getElementById("uploadProgressFill");
    const progressPercent = document.getElementById("uploadProgressPercent");
    const progressStage = document.getElementById("uploadProgressStage");

    const resultBox = document.getElementById("resultBox");
    const shareLinkInput = document.getElementById("shareLinkInput");
    const copyLinkBtn = document.getElementById("copyLinkBtn");
    const openLinkBtn = document.getElementById("openLinkBtn");
    const resetUploadBtn = document.getElementById("resetUploadBtn");
    const expiryCountdownEl = document.getElementById("resultExpiryCountdown");

    let selectedFile = null;
    let resultCountdownInterval = null;

    if (!fileInput) return;

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
        return "📄";
    }

    function setStatus(msg, type = "info") {
        if (!statusBox) return;
        statusBox.textContent = msg;
        statusBox.className = "status-message " + type;
    }

    function setProgress(percent, stageText = "") {
        if (!progressContainer || !progressFill) return;
        if (percent < 0) {
            progressContainer.style.display = "none";
            return;
        }
        progressContainer.style.display = "block";
        const clamped = Math.min(100, Math.max(0, percent));
        progressFill.style.width = clamped + "%";
        if (progressPercent) progressPercent.textContent = Math.round(clamped) + "%";
        if (progressStage && stageText) progressStage.textContent = stageText;
        if (stageText) setStatus(stageText, "info");
    }

    function handleFile(file) {
        if (!file) return;

        const MAX_SIZE = 25 * 1024 * 1024;
        if (file.size > MAX_SIZE) {
            setStatus("File is too large! Maximum allowed size is 25 MB.", "error");
            if (window.VaultXSharing) {
                window.VaultXSharing.showToast("File exceeds 25 MB limit", "error");
            }
            clearSelectedFile();
            return;
        }

        selectedFile = file;

        if (fileNameEl) fileNameEl.textContent = file.name;
        if (fileSizeEl) fileSizeEl.textContent = formatBytes(file.size);
        if (fileTypeEl) fileTypeEl.textContent = file.type || "binary / unknown";
        if (fileIconEl) fileIconEl.textContent = getFileIcon(file.name);

        if (fileInfo) fileInfo.style.display = "block";
        if (dropZone) dropZone.classList.add("has-file");
        if (resultBox) resultBox.style.display = "none";
        if (uploadBtn) {
            uploadBtn.disabled = false;
            uploadBtn.style.display = "inline-flex";
        }

        setStatus(`Ready to encrypt "${file.name}" (${formatBytes(file.size)}) with AES-256-GCM.`, "ready");
    }

    function clearSelectedFile() {
        selectedFile = null;
        if (fileInput) fileInput.value = "";
        if (fileInfo) fileInfo.style.display = "none";
        if (dropZone) dropZone.classList.remove("has-file");
        if (uploadBtn) {
            uploadBtn.disabled = true;
            uploadBtn.style.display = "inline-flex";
        }
        setProgress(-1);
        setStatus("Select or drop a file to begin client-side encryption.", "info");
    }

    if (removeFileBtn) {
        removeFileBtn.addEventListener("click", function (e) {
            e.preventDefault();
            e.stopPropagation();
            clearSelectedFile();
        });
    }

    // File Input change
    fileInput.addEventListener("change", function (e) {
        if (e.target.files && e.target.files[0]) {
            handleFile(e.target.files[0]);
        }
    });

    // Drag and Drop
    if (dropZone) {
        ["dragenter", "dragover"].forEach(eventName => {
            dropZone.addEventListener(eventName, function (e) {
                e.preventDefault();
                e.stopPropagation();
                dropZone.classList.add("drag-active");
            }, false);
        });

        ["dragleave", "drop"].forEach(eventName => {
            dropZone.addEventListener(eventName, function (e) {
                e.preventDefault();
                e.stopPropagation();
                dropZone.classList.remove("drag-active");
            }, false);
        });

        dropZone.addEventListener("drop", function (e) {
            if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0]) {
                handleFile(e.dataTransfer.files[0]);
            }
        });
    }

    // Expiry options
    function getSelectedExpiry() {
        const checkedRadio = document.querySelector('input[name="expiryOption"]:checked');
        if (checkedRadio) return checkedRadio.value;
        const expirySelect = document.getElementById("expirySelect");
        if (expirySelect) return expirySelect.value;
        return "1d";
    }

    // Live Expiry Countdown for Result Card
    function startResultCountdown(expiresAtUnix) {
        if (resultCountdownInterval) {
            clearInterval(resultCountdownInterval);
            resultCountdownInterval = null;
        }

        function updateCountdown() {
            if (!expiryCountdownEl) return;
            const now = Math.floor(Date.now() / 1000);
            const remaining = expiresAtUnix - now;

            if (remaining <= 0) {
                expiryCountdownEl.innerHTML = `<span class="badge badge-expired">🚨 Expired</span>`;
                clearInterval(resultCountdownInterval);
                return;
            }

            if (window.VaultXSharing && window.VaultXSharing.formatCountdown) {
                const info = window.VaultXSharing.formatCountdown(remaining);
                expiryCountdownEl.innerHTML = `
                    <span class="countdown-badge">
                        <span class="pulse-dot-cyan"></span>
                        Expires in <strong>${info.text}</strong>
                    </span>
                `;
            } else {
                const hours = Math.floor(remaining / 3600);
                const mins = Math.floor((remaining % 3600) / 60);
                const secs = remaining % 60;
                expiryCountdownEl.textContent = `Expires in ${hours}h ${mins}m ${secs}s`;
            }
        }

        updateCountdown();
        resultCountdownInterval = setInterval(updateCountdown, 1000);
    }

    // Upload & Encrypt Action
    if (uploadBtn) {
        uploadBtn.addEventListener("click", async function () {
            if (!selectedFile) {
                setStatus("Please select a file to encrypt and upload.", "error");
                return;
            }

            try {
                uploadBtn.disabled = true;
                setProgress(15, "Initializing WebCrypto CSPRNG & generating 256-bit AES key...");

                if (!window.VaultXEncryption) {
                    throw new Error("VaultX encryption engine is not loaded.");
                }

                // Stage 1: AES-256 Key generation & Local Encryption
                await new Promise(r => setTimeout(r, 120)); // Brief visual pacing for hackathon presentation
                setProgress(40, "Encrypting file in browser memory with AES-256-GCM...");
                const result = await window.VaultXEncryption.encryptFile(selectedFile);

                // Stage 2: Payload packaging
                setProgress(65, "Attaching 12-byte IV & 128-bit integrity tag...");
                const encryptedBlob = new Blob(
                    [result.encryptedData],
                    { type: "application/octet-stream" }
                );

                const expiry = getSelectedExpiry();
                const formData = new FormData();
                formData.append("file", encryptedBlob, "encrypted.bin");
                formData.append("iv", result.iv);
                formData.append("original_filename", selectedFile.name);
                formData.append("mime_type", selectedFile.type || "application/octet-stream");
                formData.append("expiry", expiry);

                // Stage 3: Send to server (server-blind)
                setProgress(85, "Transmitting ciphertext to zero-knowledge vault...");

                const response = await fetch("/api/upload", {
                    method: "POST",
                    body: formData
                });

                const data = await response.json();

                if (!response.ok) {
                    throw new Error(data.error || "Upload failed with status " + response.status);
                }

                // Stage 4: Success
                setProgress(100, "Local encryption & server-blind upload complete!");

                // Construct share link with key in hash fragment (RFC 3986 client-side)
                const shareLink = window.location.origin + "/f/" + encodeURIComponent(data.id) + "#" + result.key;

                // Cache in localStorage for user's dashboard view
                try {
                    const localUploads = JSON.parse(localStorage.getItem("vaultx_user_files") || "[]");
                    localUploads.unshift({
                        id: data.id,
                        name: selectedFile.name,
                        key: result.key,
                        shareLink: shareLink,
                        size: selectedFile.size,
                        uploadedAt: Date.now(),
                        expiresAt: data.expires_at
                    });
                    localStorage.setItem("vaultx_user_files", JSON.stringify(localUploads.slice(0, 50)));
                } catch (e) {
                    // Ignore quota errors
                }

                // Display Result Card
                if (resultBox) {
                    resultBox.style.display = "block";
                    if (shareLinkInput) shareLinkInput.value = shareLink;
                    if (openLinkBtn) openLinkBtn.href = shareLink;

                    // Start live expiry timer
                    if (data.expires_at) {
                        startResultCountdown(data.expires_at);
                    }

                    resultBox.scrollIntoView({ behavior: "smooth", block: "nearest" });
                }

                if (fileInfo) fileInfo.style.display = "none";
                uploadBtn.style.display = "none";
                setStatus("Complete! Share your link. The server stores ciphertext only.", "success");

                if (window.VaultXSharing) {
                    window.VaultXSharing.showToast("File encrypted & uploaded! Share link ready.", "success");
                }

            } catch (err) {
                console.error("VaultX Upload Error:", err);
                setProgress(-1);
                setStatus("Error: " + (err.message || "Encryption or upload failed."), "error");
                uploadBtn.disabled = false;
                if (window.VaultXSharing) {
                    window.VaultXSharing.showToast(err.message || "Upload failed", "error");
                }
            }
        });
    }

    // Copy Button with Animated Feedback & Toast
    if (copyLinkBtn) {
        copyLinkBtn.addEventListener("click", async function () {
            if (!shareLinkInput || !shareLinkInput.value) return;
            const link = shareLinkInput.value;

            let copied = false;
            if (window.VaultXSharing && window.VaultXSharing.copyText) {
                copied = await window.VaultXSharing.copyText(link);
            } else {
                try {
                    await navigator.clipboard.writeText(link);
                    copied = true;
                } catch (e) {
                    shareLinkInput.select();
                    copied = document.execCommand("copy");
                }
            }

            if (copied) {
                const origHtml = copyLinkBtn.innerHTML;
                copyLinkBtn.innerHTML = `
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                        <polyline points="20 6 9 17 4 12"></polyline>
                    </svg>
                    <span>Copied!</span>
                `;
                copyLinkBtn.classList.add("btn-copied");

                if (window.VaultXSharing) {
                    window.VaultXSharing.showToast("Secure share link copied to clipboard!", "success");
                }

                setTimeout(() => {
                    copyLinkBtn.innerHTML = origHtml;
                    copyLinkBtn.classList.remove("btn-copied");
                }, 2500);
            }
        });
    }

    // Reset Button
    if (resetUploadBtn) {
        resetUploadBtn.addEventListener("click", function () {
            clearSelectedFile();
            if (resultBox) resultBox.style.display = "none";
            if (resultCountdownInterval) {
                clearInterval(resultCountdownInterval);
                resultCountdownInterval = null;
            }
            window.scrollTo({ top: dropZone.offsetTop - 120, behavior: "smooth" });
        });
    }
});
