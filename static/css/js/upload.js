/**
 * VaultX - Upload Module
 * Client-side AES-256-GCM file encryption and upload handler
 */

document.addEventListener("DOMContentLoaded", function () {
    const fileInput = document.getElementById("fileInput");
    const dropZone = document.getElementById("dropZone") || document.querySelector(".upload-box");
    const uploadBtn = document.getElementById("uploadBtn");
    const fileInfo = document.getElementById("fileInfo");
    const fileNameEl = document.getElementById("fileName");
    const fileSizeEl = document.getElementById("fileSize");
    const fileTypeEl = document.getElementById("fileType");
    const statusBox = document.getElementById("status");
    const progressBar = document.getElementById("uploadProgressBar");
    const progressFill = document.getElementById("uploadProgressFill");
    const resultBox = document.getElementById("resultBox");
    const shareLinkInput = document.getElementById("shareLinkInput");
    const copyLinkBtn = document.getElementById("copyLinkBtn");
    const openLinkBtn = document.getElementById("openLinkBtn");
    const resetUploadBtn = document.getElementById("resetUploadBtn");
    const expirySelect = document.getElementById("expirySelect");

    let selectedFile = null;

    if (!fileInput) return;

    function formatBytes(bytes) {
        if (bytes === 0) return "0 Bytes";
        const k = 1024;
        const sizes = ["Bytes", "KB", "MB", "GB"];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
    }

    function setStatus(msg, type = "info") {
        if (!statusBox) return;
        statusBox.textContent = msg;
        statusBox.className = "status-message " + type;
    }

    function setProgress(percent, label = "") {
        if (!progressBar || !progressFill) return;
        progressBar.style.display = percent >= 0 ? "block" : "none";
        progressFill.style.width = Math.min(100, Math.max(0, percent)) + "%";
        if (label) setStatus(label, "info");
    }

    function handleFile(file) {
        if (!file) return;

        const MAX_SIZE = 25 * 1024 * 1024;
        if (file.size > MAX_SIZE) {
            setStatus("File is too large! Maximum allowed size is 25 MB.", "error");
            if (fileInput) fileInput.value = "";
            selectedFile = null;
            if (fileInfo) fileInfo.style.display = "none";
            if (uploadBtn) uploadBtn.disabled = true;
            return;
        }

        selectedFile = file;

        if (fileNameEl) fileNameEl.textContent = file.name;
        if (fileSizeEl) fileSizeEl.textContent = formatBytes(file.size);
        if (fileTypeEl) fileTypeEl.textContent = file.type || "binary / unknown";

        if (fileInfo) fileInfo.style.display = "block";
        if (resultBox) resultBox.style.display = "none";
        if (uploadBtn) {
            uploadBtn.disabled = false;
            uploadBtn.style.display = "inline-flex";
        }

        setStatus(`Selected: "${file.name}" (${formatBytes(file.size)}). Ready for client-side encryption.`, "ready");
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

    // Expiry radio/pills
    function getSelectedExpiry() {
        if (expirySelect) return expirySelect.value;
        const checkedRadio = document.querySelector('input[name="expiryOption"]:checked');
        if (checkedRadio) return checkedRadio.value;
        return "1d";
    }

    // Upload & Encrypt
    if (uploadBtn) {
        uploadBtn.addEventListener("click", async function () {
            if (!selectedFile) {
                setStatus("Please select a file to encrypt and upload.", "error");
                return;
            }

            try {
                uploadBtn.disabled = true;
                setProgress(20, "Generating 256-bit AES-GCM encryption key locally...");

                if (!window.VaultXEncryption) {
                    throw new Error("VaultX encryption engine not loaded.");
                }

                // 1. Client-Side Encryption
                setProgress(45, "Encrypting file in browser memory with AES-256-GCM...");
                const result = await window.VaultXEncryption.encryptFile(selectedFile);

                // 2. Prepare encrypted payload
                setProgress(70, "Packaging encrypted ciphertext & initialization vector...");
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

                // 3. Upload to server
                setProgress(85, "Sending encrypted file to VaultX storage (server-blind)...");

                const response = await fetch("/api/upload", {
                    method: "POST",
                    body: formData
                });

                const data = await response.json();

                if (!response.ok) {
                    throw new Error(data.error || "Upload failed with status " + response.status);
                }

                setProgress(100, "File encrypted and uploaded successfully!");

                // 4. Construct share link with key in hash
                const shareLink = window.location.origin + "/f/" + encodeURIComponent(data.id) + "#" + result.key;

                // Cache to localStorage for user's dashboard view
                try {
                    const localUploads = JSON.parse(localStorage.getItem("vaultx_user_files") || "[]");
                    localUploads.unshift({
                        id: data.id,
                        name: selectedFile.name,
                        key: result.key,
                        shareLink: shareLink,
                        uploadedAt: Date.now()
                    });
                    localStorage.setItem("vaultx_user_files", JSON.stringify(localUploads.slice(0, 50)));
                } catch (e) {
                    // Ignore localStorage quota/private errors
                }

                // 5. Display Result
                if (resultBox) {
                    resultBox.style.display = "block";
                    if (shareLinkInput) shareLinkInput.value = shareLink;
                    if (openLinkBtn) openLinkBtn.href = shareLink;
                    resultBox.scrollIntoView({ behavior: "smooth", block: "nearest" });
                }

                if (fileInfo) fileInfo.style.display = "none";
                uploadBtn.style.display = "none";
                setStatus("Complete! Share your link. The server cannot read your file.", "success");

            } catch (err) {
                console.error("VaultX Upload Error:", err);
                setProgress(-1);
                setStatus("Error: " + (err.message || "Encryption or upload failed."), "error");
                uploadBtn.disabled = false;
            }
        });
    }

    // Copy Button
    if (copyLinkBtn) {
        copyLinkBtn.addEventListener("click", async function () {
            if (!shareLinkInput) return;
            try {
                await navigator.clipboard.writeText(shareLinkInput.value);
                const origText = copyLinkBtn.innerHTML;
                copyLinkBtn.innerHTML = "✓ Link Copied!";
                copyLinkBtn.classList.add("copied");
                setTimeout(() => {
                    copyLinkBtn.innerHTML = origText;
                    copyLinkBtn.classList.remove("copied");
                }, 2500);
            } catch (e) {
                shareLinkInput.select();
                document.execCommand("copy");
                copyLinkBtn.textContent = "✓ Link Copied!";
            }
        });
    }

    // Reset Button
    if (resetUploadBtn) {
        resetUploadBtn.addEventListener("click", function () {
            selectedFile = null;
            if (fileInput) fileInput.value = "";
            if (fileInfo) fileInfo.style.display = "none";
            if (resultBox) resultBox.style.display = "none";
            if (uploadBtn) {
                uploadBtn.style.display = "inline-flex";
                uploadBtn.disabled = true;
            }
            setProgress(-1);
            setStatus("Select a file to get started.", "info");
        });
    }
});
