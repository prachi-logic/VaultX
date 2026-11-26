/**
 * VaultX - Dashboard Module
 * Displays real-time vault metrics, stored encrypted files, and access logs.
 */

import { formatBytes, formatTime } from "./sharing.js";

const fileList = document.querySelector("#file-list");
const logList = document.querySelector("#log-list");
const totalFilesEl = document.querySelector("#stat-total-files");
const activeFilesEl = document.querySelector("#stat-active-files");
const totalDownloadsEl = document.querySelector("#stat-total-downloads");
const totalSizeEl = document.querySelector("#stat-total-size");

function getStoredKey(fileId) {
    try {
        const stored = JSON.parse(localStorage.getItem("vaultx_user_files") || "[]");
        const found = stored.find(f => f.id === fileId);
        return found ? found.key : null;
    } catch (e) {
        return null;
    }
}

function createFileCard(file) {
    const card = document.createElement("article");
    card.className = "dashboard-card file-card-item";

    const isExpired = file.expired;
    const key = getStoredKey(file.id);
    const fullShareLink = key ? `${window.location.origin}/f/${file.id}#${key}` : null;

    card.innerHTML = `
        <div class="file-card-header">
            <div class="file-card-title">
                <span class="file-icon">📄</span>
                <div>
                    <h3 class="file-name" title="${file.filename}">${file.filename}</h3>
                    <code class="file-id">ID: ${file.id}</code>
                </div>
            </div>
            <span class="badge ${isExpired ? 'badge-expired' : 'badge-active'}">
                ${isExpired ? '● Expired' : '● Active'}
            </span>
        </div>

        <div class="file-meta-grid">
            <div>
                <span class="meta-label">Size:</span>
                <strong>${formatBytes(file.size)}</strong>
            </div>
            <div>
                <span class="meta-label">Uploaded:</span>
                <span>${formatTime(file.created_at)}</span>
            </div>
            <div>
                <span class="meta-label">Expires:</span>
                <span>${formatTime(file.expires_at)}</span>
            </div>
            <div>
                <span class="meta-label">Downloads:</span>
                <strong>${file.downloads}</strong>
            </div>
        </div>

        <div class="file-card-actions">
            ${
                fullShareLink ? `
                <button type="button" class="btn btn-secondary btn-sm copy-link-btn" data-link="${fullShareLink}">
                    📋 Copy Share Link
                </button>
                <a href="${fullShareLink}" target="_blank" class="btn btn-secondary btn-sm">
                    👁️ View / Open ↗
                </a>
                ` : `
                <span class="key-note" title="Decryption key is stored in the browser of the user who uploaded this file.">
                    🔒 Key protected
                </span>
                `
            }
            <button type="button" class="btn btn-danger btn-sm revoke-btn" data-id="${file.id}">
                🗑️ Revoke File
            </button>
        </div>
    `;

    // Revoke button listener
    const revokeBtn = card.querySelector(".revoke-btn");
    revokeBtn.addEventListener("click", async () => {
        if (!confirm(`Are you sure you want to permanently revoke and delete "${file.filename}"? This action cannot be undone.`)) {
            return;
        }
        try {
            revokeBtn.disabled = true;
            revokeBtn.textContent = "Revoking...";
            const res = await fetch(`/api/files/${file.id}`, { method: "DELETE" });
            if (res.ok) {
                // Also clean up local storage
                try {
                    const stored = JSON.parse(localStorage.getItem("vaultx_user_files") || "[]");
                    const updated = stored.filter(f => f.id !== file.id);
                    localStorage.setItem("vaultx_user_files", JSON.stringify(updated));
                } catch (e) {}
                await loadDashboard();
            } else {
                alert("Failed to revoke file.");
                revokeBtn.disabled = false;
                revokeBtn.textContent = "🗑️ Revoke File";
            }
        } catch (err) {
            console.error("Revoke error:", err);
            alert("Error connecting to server.");
            revokeBtn.disabled = false;
            revokeBtn.textContent = "🗑️ Revoke File";
        }
    });

    // Copy link listener
    const copyBtn = card.querySelector(".copy-link-btn");
    if (copyBtn) {
        copyBtn.addEventListener("click", async () => {
            const link = copyBtn.getAttribute("data-link");
            try {
                await navigator.clipboard.writeText(link);
                const prev = copyBtn.textContent;
                copyBtn.textContent = "✓ Copied!";
                setTimeout(() => copyBtn.textContent = prev, 2000);
            } catch (e) {
                prompt("Copy this share link:", link);
            }
        });
    }

    return card;
}

export async function loadDashboard() {
    try {
        const response = await fetch("/api/files");
        if (!response.ok) {
            throw new Error("Failed to load dashboard data");
        }
        const data = await response.json();

        // 1. Update Stats
        if (data.stats) {
            if (totalFilesEl) totalFilesEl.textContent = data.stats.total_files || 0;
            if (activeFilesEl) activeFilesEl.textContent = data.stats.active_files || 0;
            if (totalDownloadsEl) totalDownloadsEl.textContent = data.stats.total_downloads || 0;
            if (totalSizeEl) totalSizeEl.textContent = formatBytes(data.stats.total_bytes || 0);
        }

        // 2. Render Files List
        if (fileList) {
            fileList.replaceChildren();
            if (!data.files || data.files.length === 0) {
                fileList.innerHTML = `
                    <div class="empty-state">
                        <div class="empty-icon">📁</div>
                        <h3>No files in the vault yet</h3>
                        <p>Upload a file with client-side encryption to get started.</p>
                        <a href="/upload" class="primary-btn" style="margin-top: 15px;">Upload a File ↗</a>
                    </div>
                `;
            } else {
                for (const file of data.files) {
                    fileList.append(createFileCard(file));
                }
            }
        }

        // 3. Render Access Logs
        if (logList) {
            logList.replaceChildren();
            if (!data.logs || data.logs.length === 0) {
                logList.innerHTML = `
                    <div class="empty-state">
                        <p>No activity recorded yet.</p>
                    </div>
                `;
            } else {
                for (const log of data.logs) {
                    const row = document.createElement("div");
                    row.className = "log-item";

                    let eventBadgeClass = "badge-event-default";
                    let eventIcon = "◈";
                    if (log.event === "upload") {
                        eventBadgeClass = "badge-event-upload";
                        eventIcon = "↑";
                    } else if (log.event === "view") {
                        eventBadgeClass = "badge-event-view";
                        eventIcon = "👁";
                    } else if (log.event === "download") {
                        eventBadgeClass = "badge-event-download";
                        eventIcon = "↓";
                    }

                    row.innerHTML = `
                        <div class="log-event">
                            <span class="badge ${eventBadgeClass}">${eventIcon} ${log.event.toUpperCase()}</span>
                            <code class="log-file-id">${log.file_id}</code>
                        </div>
                        <span class="log-timestamp">${formatTime(log.created_at)}</span>
                    `;
                    logList.append(row);
                }
            }
        }
    } catch (err) {
        console.error("Dashboard load failed:", err);
        if (fileList) {
            fileList.innerHTML = `<div class="status-message error">Failed to load files from server.</div>`;
        }
    }
}

document.addEventListener("DOMContentLoaded", loadDashboard);
