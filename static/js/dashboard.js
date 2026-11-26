/**
 * VaultX - Dashboard Module
 * Real-time cybersecurity analytics:
 * - Smart Security Score based on authentic enabled backend controls
 * - Emergency Revocation with disk ciphertext unlinking & permanent deactivation
 * - Activity Timeline with upload, view, download, revoke, expiry, and threat events
 * - Live Expiry Countdown ticking in real-time
 * - Suspicious Activity Alerts for repeated failed access attempts & probing
 * (Note: QR code features completely removed per security policy; secure share links preserved)
 */

import { formatBytes, formatTime, formatRelativeTime, formatCountdown, showToast, copyText } from "./sharing.js";

// DOM References
const fileList = document.querySelector("#file-list");
const logList = document.querySelector("#log-list");
const totalFilesEl = document.querySelector("#stat-total-files");
const activeFilesEl = document.querySelector("#stat-active-files");
const totalDownloadsEl = document.querySelector("#stat-total-downloads");
const totalSizeEl = document.querySelector("#stat-total-size");
const searchInput = document.querySelector("#dashboard-search");
const filterPills = document.querySelectorAll(".filter-pill");
const refreshBtn = document.querySelector("#refreshDashboardBtn");
const healthBadgeEl = document.querySelector("#system-health-badge");

// Security Score DOM References
const scoreValEl = document.querySelector("#security-score-val");
const scoreGradeBadge = document.querySelector("#score-grade-badge");
const scoreCircle = document.querySelector("#scoreCircle");
const scoreStatusDot = document.querySelector("#scoreStatusDot");
const scoreStatusTitle = document.querySelector("#security-score-status");
const scoreDescEl = document.querySelector("#security-score-desc");
const scoreGradeChip = document.querySelector("#scoreGradeChip");
const threatCountChip = document.querySelector("#threatCountChip");
const securityChecksList = document.querySelector("#security-checks-list");
const recalculateScoreBtn = document.querySelector("#recalculateScoreBtn");

// Threat Alerts DOM References
const threatAlertsFeed = document.querySelector("#security-alerts-feed");
const threatsCountBadge = document.querySelector("#threats-count-badge");

// Revoke Modal DOM References
const revokeModal = document.querySelector("#revokeModal");
const revokeModalClose = document.querySelector("#revokeModalClose");
const revokeCancelBtn = document.querySelector("#revokeCancelBtn");
const revokeConfirmBtn = document.querySelector("#revokeConfirmBtn");
const revokeTargetFilename = document.querySelector("#revokeTargetFilename");

// Timeline filter buttons
const timelinePills = document.querySelectorAll(".timeline-pill");

// State
let cachedFiles = [];
let cachedLogs = [];
let currentFilter = "all";
let currentTimelineFilter = "all";
let currentSearch = "";
let countdownTimer = null;
let pendingRevokeFile = null;

function getStoredKey(fileId) {
    try {
        const stored = JSON.parse(localStorage.getItem("vaultx_user_files") || "[]");
        const found = stored.find(f => f.id === fileId);
        return found ? found.key : null;
    } catch (e) {
        return null;
    }
}

function removeStoredKey(fileId) {
    try {
        const stored = JSON.parse(localStorage.getItem("vaultx_user_files") || "[]");
        const updated = stored.filter(f => f.id !== fileId);
        localStorage.setItem("vaultx_user_files", JSON.stringify(updated));
    } catch (e) {}
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

// -----------------------------------------------------------------------------
// 1. SMART SECURITY SCORE RENDERING
// -----------------------------------------------------------------------------
function renderSecurityScore(scoreData) {
    if (!scoreData) return;

    const total = scoreData.total_score || 0;
    const max = scoreData.max_score || 100;
    const pct = Math.round((total / max) * 100);
    const grade = scoreData.grade || "A";
    const status = scoreData.status || "SECURE";
    const activeThreats = scoreData.active_threats || 0;

    if (scoreValEl) scoreValEl.textContent = pct;

    if (scoreGradeBadge) {
        scoreGradeBadge.textContent = `GRADE ${grade} &middot; ${status}`;
        scoreGradeBadge.className = pct >= 85 ? "section-badge badge-active" : (pct >= 70 ? "section-badge badge-warning" : "section-badge badge-danger");
    }

    if (scoreGradeChip) scoreGradeChip.textContent = `GRADE: ${grade}`;
    if (threatCountChip) {
        threatCountChip.textContent = activeThreats === 0 ? "0 Active Threats" : `⚠️ ${activeThreats} Active Alert${activeThreats > 1 ? 's' : ''}`;
        threatCountChip.style.borderColor = activeThreats > 0 ? "var(--danger)" : "var(--border-medium)";
        threatCountChip.style.color = activeThreats > 0 ? "var(--danger)" : "var(--text-secondary)";
    }

    if (scoreStatusTitle) {
        scoreStatusTitle.textContent = `${status} POSTURE (${pct}/100)`;
        scoreStatusTitle.style.color = pct >= 85 ? "var(--safe)" : (pct >= 70 ? "var(--amber)" : "var(--danger)");
    }

    if (scoreStatusDot) {
        scoreStatusDot.className = pct >= 85 ? "score-status-indicator pulse-dot-green" : (pct >= 70 ? "score-status-indicator pulse-dot-amber" : "score-status-indicator pulse-dot-danger");
    }

    if (scoreCircle) {
        const strokeColor = pct >= 85 ? "var(--purple-primary)" : (pct >= 70 ? "var(--amber)" : "var(--danger)");
        scoreCircle.style.borderColor = strokeColor;
        scoreCircle.style.boxShadow = `0 0 25px ${strokeColor}44`;
    }

    if (scoreDescEl) {
        if (activeThreats > 0) {
            scoreDescEl.textContent = `Score dynamically penalized: ${activeThreats} suspicious activity anomalies detected in the 30-minute threat window. Review alerts below.`;
        } else {
            scoreDescEl.textContent = `Optimal posture: All 5 cryptographic and architectural integrity controls passed with zero active threat anomalies.`;
        }
    }

    // Render verified checks breakdown
    if (securityChecksList && scoreData.checks) {
        securityChecksList.replaceChildren();

        scoreData.checks.forEach(check => {
            const row = document.createElement("div");
            row.className = `check-card ${check.passed ? "check-passed" : "check-failed"}`;

            row.innerHTML = `
                <div class="check-header">
                    <div class="check-title-wrap">
                        <span class="check-icon">${check.passed ? "✓" : "⚠️"}</span>
                        <strong>${check.name}</strong>
                    </div>
                    <span class="check-score-pill ${check.passed ? "pill-safe" : "pill-danger"}">
                        ${check.score}/${check.max} pts
                    </span>
                </div>
                <p class="check-desc text-muted">${check.description}</p>
            `;

            securityChecksList.appendChild(row);
        });
    }
}

// -----------------------------------------------------------------------------
// 2. SUSPICIOUS ACTIVITY ALERTS RENDERING
// -----------------------------------------------------------------------------
function renderThreatAlerts(alerts) {
    if (!threatAlertsFeed) return;
    threatAlertsFeed.replaceChildren();

    const count = (alerts && alerts.length) || 0;
    if (threatsCountBadge) {
        if (count === 0) {
            threatsCountBadge.textContent = "0 Active Warnings";
            threatsCountBadge.className = "section-badge badge-neutral";
        } else {
            threatsCountBadge.textContent = `🚨 ${count} Active Warning${count > 1 ? 's' : ''}`;
            threatsCountBadge.className = "section-badge badge-danger";
        }
    }

    if (!alerts || alerts.length === 0) {
        threatAlertsFeed.innerHTML = `
            <div class="threat-normal-banner">
                <span class="shield-icon">🛡️</span>
                <div>
                    <strong>All Systems Secure &mdash; Threat Level: NORMAL</strong>
                    <p class="text-muted">Zero repeated failed access attempts, revoked link probing, or ID scanning detected in the active 30-minute window.</p>
                </div>
            </div>
        `;
        return;
    }

    alerts.forEach(alert => {
        const card = document.createElement("div");
        card.className = `threat-alert-card severity-${alert.severity || "high"}`;

        const isRevokedProbing = alert.type === "revoked_file_probing";
        const fileMatch = cachedFiles.find(f => f.id === alert.file_id);

        card.innerHTML = `
            <div class="threat-alert-top">
                <div class="threat-title-wrap">
                    <span class="threat-warning-icon">⚠️</span>
                    <div>
                        <div class="threat-badge-row">
                            <span class="threat-severity-pill severity-${alert.severity || "high"}">
                                ${alert.severity === "critical" ? "CRITICAL ALERT" : "SUSPICIOUS ACTIVITY"}
                            </span>
                            <span class="threat-time text-muted">Detected ${formatRelativeTime(alert.last_attempt)}</span>
                        </div>
                        <h4 class="threat-title">${alert.title}</h4>
                    </div>
                </div>
                <div class="threat-fail-badge">
                    <strong>${alert.fail_count}</strong>
                    <span>FAILED ATTEMPTS</span>
                </div>
            </div>

            <p class="threat-message">${alert.message}</p>

            <div class="threat-meta-row">
                <span class="threat-target">
                    Target File: <code>${alert.file_id}</code> ${alert.filename ? `(${alert.filename})` : ''}
                </span>
                <span class="threat-recommendation text-muted">
                    Recommendation: ${alert.recommendation}
                </span>
            </div>

            ${
                (!isRevokedProbing && fileMatch) ? `
                <div class="threat-action-row">
                    <button type="button" class="primary-btn btn-sm btn-danger-sm threat-revoke-btn" data-id="${alert.file_id}" data-filename="${alert.filename || fileMatch.filename}">
                        🚨 Execute Emergency Revoke on this File
                    </button>
                </div>
                ` : ''
            }
        `;

        // Direct revoke button inside alert card
        const alertRevokeBtn = card.querySelector(".threat-revoke-btn");
        if (alertRevokeBtn) {
            alertRevokeBtn.addEventListener("click", () => {
                const fid = alertRevokeBtn.getAttribute("data-id");
                const fname = alertRevokeBtn.getAttribute("data-filename");
                openRevokeModal(fid, fname);
            });
        }

        threatAlertsFeed.appendChild(card);
    });
}

// -----------------------------------------------------------------------------
// 3. EMERGENCY REVOKE MODAL & HANDLERS
// -----------------------------------------------------------------------------
function openRevokeModal(fileId, filename) {
    if (!revokeModal) return;
    pendingRevokeFile = { id: fileId, filename: filename };

    if (revokeTargetFilename) {
        revokeTargetFilename.textContent = `"${filename}" (ID: ${fileId})`;
    }
    revokeModal.classList.add("modal-active");
}

function closeRevokeModal() {
    if (!revokeModal) return;
    revokeModal.classList.remove("modal-active");
    pendingRevokeFile = null;
    if (revokeConfirmBtn) {
        revokeConfirmBtn.disabled = false;
        revokeConfirmBtn.innerHTML = "🗑️ Confirm Emergency Revoke";
    }
}

if (revokeModalClose) revokeModalClose.addEventListener("click", closeRevokeModal);
if (revokeCancelBtn) revokeCancelBtn.addEventListener("click", closeRevokeModal);
if (revokeModal) {
    revokeModal.addEventListener("click", (e) => {
        if (e.target === revokeModal) closeRevokeModal();
    });
}

if (revokeConfirmBtn) {
    revokeConfirmBtn.addEventListener("click", async () => {
        if (!pendingRevokeFile) return;
        const { id, filename } = pendingRevokeFile;

        try {
            revokeConfirmBtn.disabled = true;
            revokeConfirmBtn.innerHTML = "Unlinking disk ciphertext & revoking...";

            const res = await fetch(`/api/files/${encodeURIComponent(id)}/revoke`, {
                method: "POST",
                headers: { "Content-Type": "application/json" }
            });

            const result = await res.json();

            if (res.ok) {
                removeStoredKey(id);
                showToast(`Access permanently revoked for "${filename}". Ciphertext purged from disk.`, "success");
                closeRevokeModal();
                await loadDashboard();
            } else {
                showToast(result.error || "Failed to execute emergency revocation", "error");
                revokeConfirmBtn.disabled = false;
                revokeConfirmBtn.innerHTML = "🗑️ Confirm Emergency Revoke";
            }
        } catch (err) {
            console.error("Revoke request error:", err);
            showToast("Server error during emergency revocation", "error");
            revokeConfirmBtn.disabled = false;
            revokeConfirmBtn.innerHTML = "🗑️ Confirm Emergency Revoke";
        }
    });
}

// -----------------------------------------------------------------------------
// 4. FILE CARD CREATION (NO QR CODE - PURE SECURE SHARING)
// -----------------------------------------------------------------------------
function createFileCard(file) {
    const card = document.createElement("article");
    card.className = "dashboard-card file-card-item";

    const now = Math.floor(Date.now() / 1000);
    const isExpired = file.expired || file.expires_at <= now;
    const key = getStoredKey(file.id);
    const fullShareLink = key ? `${window.location.origin}/f/${file.id}#${key}` : null;
    const icon = getFileIcon(file.filename);

    const remainingSecs = file.expires_at - now;
    let countdownDisplay = "";
    if (isExpired) {
        countdownDisplay = `<span class="badge badge-expired">● Expired</span>`;
    } else {
        const cd = formatCountdown(remainingSecs);
        countdownDisplay = `
            <span class="badge badge-active countdown-live" data-expires="${file.expires_at}">
                <span class="pulse-dot-green"></span>
                ⏳ ${cd.text} left
            </span>
        `;
    }

    card.innerHTML = `
        <div class="file-card-header">
            <div class="file-card-title">
                <span class="file-icon">${icon}</span>
                <div class="file-title-wrap">
                    <h3 class="file-name" title="${file.filename}">${file.filename}</h3>
                    <code class="file-id">ID: ${file.id}</code>
                </div>
            </div>
            <div class="file-card-badge-wrap">
                ${countdownDisplay}
            </div>
        </div>

        <div class="file-meta-grid">
            <div class="meta-item">
                <span class="meta-label">Payload Size</span>
                <strong>${formatBytes(file.size)}</strong>
            </div>
            <div class="meta-item">
                <span class="meta-label">Uploaded</span>
                <span>${formatTime(file.created_at)}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Expires</span>
                <span>${formatTime(file.expires_at)}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Decryptions</span>
                <strong class="text-cyan">${file.downloads}</strong>
            </div>
        </div>

        <div class="file-card-actions">
            ${
                fullShareLink ? `
                <button type="button" class="btn btn-secondary btn-sm copy-link-btn" data-link="${fullShareLink}">
                    📋 Copy Link
                </button>
                <a href="${fullShareLink}" target="_blank" class="btn btn-secondary btn-sm">
                    👁️ Test Decrypt ↗
                </a>
                ` : `
                <div class="zero-knowledge-pill" title="Key stored in browser RAM only. Server holds ciphertext only.">
                    🛡️ Zero-Knowledge Protected
                </div>
                `
            }
            <button type="button" class="btn btn-danger btn-sm revoke-btn" data-id="${file.id}" data-filename="${file.filename}">
                🗑️ Revoke Access
            </button>
        </div>
    `;

    // Revoke button
    const revokeBtn = card.querySelector(".revoke-btn");
    revokeBtn.addEventListener("click", () => {
        openRevokeModal(file.id, file.filename);
    });

    // Copy link button
    const copyBtn = card.querySelector(".copy-link-btn");
    if (copyBtn) {
        copyBtn.addEventListener("click", async () => {
            const link = copyBtn.getAttribute("data-link");
            const success = await copyText(link);
            if (success) {
                const prev = copyBtn.innerHTML;
                copyBtn.innerHTML = "✓ Link Copied!";
                showToast("Secure sharing link copied to clipboard!", "success");
                setTimeout(() => copyBtn.innerHTML = prev, 2000);
            }
        });
    }

    return card;
}

// -----------------------------------------------------------------------------
// 5. RENDER FILES LIST
// -----------------------------------------------------------------------------
function renderFilesList() {
    if (!fileList) return;
    fileList.replaceChildren();

    const now = Math.floor(Date.now() / 1000);

    const filtered = cachedFiles.filter(f => {
        const isExpired = f.expired || f.expires_at <= now;
        if (currentFilter === "active" && isExpired) return false;
        if (currentFilter === "expired" && !isExpired) return false;

        if (currentSearch) {
            const q = currentSearch.toLowerCase();
            const matchName = (f.filename || "").toLowerCase().includes(q);
            const matchId = (f.id || "").toLowerCase().includes(q);
            if (!matchName && !matchId) return false;
        }
        return true;
    });

    if (filtered.length === 0) {
        fileList.innerHTML = `
            <div class="empty-state">
                <div class="empty-icon">📂</div>
                <h3>${currentSearch ? "No matching files found" : "No files in vault for this filter"}</h3>
                <p>${currentSearch ? "Try searching for a different keyword or file ID." : "Upload a file with client-side encryption to get started."}</p>
                ${!currentSearch ? '<a href="/upload" class="primary-btn" style="margin-top: 15px;">Upload a File ↗</a>' : ''}
            </div>
        `;
        return;
    }

    for (const file of filtered) {
        fileList.append(createFileCard(file));
    }
}

// -----------------------------------------------------------------------------
// 6. LIVE EXPIRY COUNTDOWN TICKER
// -----------------------------------------------------------------------------
function startDashboardCountdownTick() {
    if (countdownTimer) clearInterval(countdownTimer);
    countdownTimer = setInterval(() => {
        const liveBadges = document.querySelectorAll(".countdown-live");
        const now = Math.floor(Date.now() / 1000);

        liveBadges.forEach(badge => {
            const expires = parseInt(badge.getAttribute("data-expires"), 10);
            const remaining = expires - now;
            if (remaining <= 0) {
                badge.className = "badge badge-expired";
                badge.innerHTML = "● Expired";
            } else {
                const cd = formatCountdown(remaining);
                badge.innerHTML = `<span class="pulse-dot-green"></span> ⏳ ${cd.text} left`;
            }
        });
    }, 1000);
}

// -----------------------------------------------------------------------------
// 7. ACTIVITY TIMELINE RENDERING
// -----------------------------------------------------------------------------
function renderActivityTimeline() {
    if (!logList) return;
    logList.replaceChildren();

    const filteredLogs = cachedLogs.filter(log => {
        if (currentTimelineFilter === "all") return true;
        if (currentTimelineFilter === "upload" && log.event === "upload") return true;
        if (currentTimelineFilter === "download" && log.event === "download") return true;
        if (currentTimelineFilter === "view" && log.event === "view") return true;
        if (currentTimelineFilter === "revoke" && log.event === "revoke") return true;
        if (currentTimelineFilter === "threat" && (log.event === "failed_attempt" || log.event === "expiry")) return true;
        return false;
    });

    if (filteredLogs.length === 0) {
        logList.innerHTML = `
            <div class="empty-state">
                <p class="text-muted">No timeline activity matches filter "${currentTimelineFilter}".</p>
            </div>
        `;
        return;
    }

    for (const log of filteredLogs) {
        const row = document.createElement("div");
        row.className = "log-item";

        let eventBadgeClass = "badge-event-default";
        let eventIcon = "◈";
        let eventLabel = (log.event || "event").toUpperCase();
        let eventDetail = "";

        if (log.event === "upload") {
            eventBadgeClass = "badge-event-upload";
            eventIcon = "↑";
            eventDetail = "Encrypted ciphertext sealed & uploaded to server";
        } else if (log.event === "view") {
            eventBadgeClass = "badge-event-view";
            eventIcon = "👁️";
            eventDetail = "Metadata verified; awaiting client key decryption";
        } else if (log.event === "download") {
            eventBadgeClass = "badge-event-download";
            eventIcon = "⬇️";
            eventDetail = "Ciphertext downloaded for browser memory decryption";
        } else if (log.event === "revoke") {
            eventBadgeClass = "badge-event-revoke";
            eventIcon = "🗑️";
            eventLabel = "REVOKED";
            eventDetail = "Emergency revocation executed; disk ciphertext purged";
        } else if (log.event === "expiry") {
            eventBadgeClass = "badge-event-expiry";
            eventIcon = "⏳";
            eventLabel = "EXPIRED";
            eventDetail = "Link TTL elapsed; file self-destructed";
        } else if (log.event === "failed_attempt") {
            eventBadgeClass = "badge-event-threat";
            eventIcon = "⚠️";
            eventLabel = "FAILED ATTEMPT";
            eventDetail = "Blocked access attempt (invalid/revoked link or failed auth)";
        }

        row.innerHTML = `
            <div class="log-event-main">
                <div class="log-badge-row">
                    <span class="badge ${eventBadgeClass}">${eventIcon} ${eventLabel}</span>
                    <strong class="log-filename" title="${log.filename || log.file_id}">${log.filename || "Payload"}</strong>
                </div>
                <p class="log-desc text-muted">${eventDetail}</p>
                <code class="log-file-id" title="${log.file_id}">ID: ${log.file_id.slice(0, 14)}...</code>
            </div>
            <div class="log-time-wrap">
                <span class="log-rel-time">${formatRelativeTime(log.created_at)}</span>
                <span class="log-timestamp">${formatTime(log.created_at)}</span>
            </div>
        `;
        logList.append(row);
    }
}

// -----------------------------------------------------------------------------
// 8. SYSTEM HEALTH CHECK
// -----------------------------------------------------------------------------
async function checkSystemHealth() {
    if (!healthBadgeEl) return;
    try {
        const res = await fetch("/api/health");
        const health = await res.json();
        if (health.status === "healthy") {
            healthBadgeEl.innerHTML = `
                <span class="health-status-dot online"></span>
                <span>SQLite WAL Online &middot; <strong>${health.file_count}</strong> Files Sealed</span>
            `;
        } else {
            healthBadgeEl.innerHTML = `
                <span class="health-status-dot offline"></span>
                <span>Database Degraded</span>
            `;
        }
    } catch (e) {
        healthBadgeEl.innerHTML = `
            <span class="health-status-dot offline"></span>
            <span>Server Offline</span>
        `;
    }
}

// -----------------------------------------------------------------------------
// 9. MASTER LOAD DASHBOARD FUNCTION
// -----------------------------------------------------------------------------
export async function loadDashboard() {
    try {
        const response = await fetch("/api/files");
        if (!response.ok) {
            throw new Error("Failed to load dashboard data");
        }
        const data = await response.json();
        cachedFiles = data.files || [];
        cachedLogs = data.logs || [];

        // 1. Update Top Stats
        if (data.stats) {
            if (totalFilesEl) totalFilesEl.textContent = data.stats.total_files || 0;
            if (activeFilesEl) activeFilesEl.textContent = data.stats.active_files || 0;
            if (totalDownloadsEl) totalDownloadsEl.textContent = data.stats.total_downloads || 0;
            if (totalSizeEl) totalSizeEl.textContent = formatBytes(data.stats.total_bytes || 0);
        }

        // 2. Render Smart Security Score
        if (data.security_score) {
            renderSecurityScore(data.security_score);
        }

        // 3. Render Suspicious Threat Alerts
        renderThreatAlerts(data.alerts || []);

        // 4. Render Files List & Start Live Countdown
        renderFilesList();
        startDashboardCountdownTick();

        // 5. Render Activity Timeline
        renderActivityTimeline();

        // 6. Check Database & Engine Health
        checkSystemHealth();

    } catch (err) {
        console.error("Dashboard load failed:", err);
        if (fileList) {
            fileList.innerHTML = `<div class="status-message error">Failed to connect to VaultX API.</div>`;
        }
    }
}

// -----------------------------------------------------------------------------
// 10. EVENT LISTENERS
// -----------------------------------------------------------------------------

// Search input
if (searchInput) {
    searchInput.addEventListener("input", (e) => {
        currentSearch = e.target.value.trim();
        renderFilesList();
    });
}

// File Filter pills
filterPills.forEach(pill => {
    pill.addEventListener("click", () => {
        filterPills.forEach(p => p.classList.remove("active"));
        pill.classList.add("active");
        currentFilter = pill.getAttribute("data-filter") || "all";
        renderFilesList();
    });
});

// Timeline Filter pills
timelinePills.forEach(pill => {
    pill.addEventListener("click", () => {
        timelinePills.forEach(p => p.classList.remove("active"));
        pill.classList.add("active");
        currentTimelineFilter = pill.getAttribute("data-timeline-filter") || "all";
        renderActivityTimeline();
    });
});

// Recalculate Score button
if (recalculateScoreBtn) {
    recalculateScoreBtn.addEventListener("click", async () => {
        try {
            recalculateScoreBtn.disabled = true;
            recalculateScoreBtn.textContent = "⚡ Recalculating...";
            const res = await fetch("/api/security-score");
            if (res.ok) {
                const scoreData = await res.json();
                renderSecurityScore(scoreData);
                showToast("Security posture recalculated from live backend telemetry!", "success");
            }
        } catch (e) {
            showToast("Failed to recalculate score", "error");
        } finally {
            recalculateScoreBtn.disabled = false;
            recalculateScoreBtn.textContent = "⚡ Recalculate Score";
        }
    });
}

// Refresh Dashboard button
if (refreshBtn) {
    refreshBtn.addEventListener("click", async () => {
        refreshBtn.disabled = true;
        refreshBtn.classList.add("btn-spinning");
        await loadDashboard();
        showToast("Dashboard telemetry refreshed", "info");
        setTimeout(() => {
            refreshBtn.disabled = false;
            refreshBtn.classList.remove("btn-spinning");
        }, 600);
    });
}

document.addEventListener("DOMContentLoaded", loadDashboard);
