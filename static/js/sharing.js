/**
 * VaultX - Sharing & Utility Helpers
 * Provides formatting, clipboard handling, live countdown calculation, and toast notifications.
 */

export function formatBytes(bytes) {
    if (!bytes || bytes === 0) return "0 Bytes";
    const k = 1024;
    const sizes = ["Bytes", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
}

export function formatTime(unixSeconds) {
    if (!unixSeconds) return "N/A";
    return new Date(unixSeconds * 1000).toLocaleString(undefined, {
        year: "numeric",
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit"
    });
}

export function formatRelativeTime(unixSeconds) {
    if (!unixSeconds) return "N/A";
    const diff = Math.floor(Date.now() / 1000) - unixSeconds;
    if (diff < 10) return "just now";
    if (diff < 60) return `${diff}s ago`;
    const mins = Math.floor(diff / 60);
    if (mins < 60) return `${mins}m ago`;
    const hours = Math.floor(mins / 60);
    if (hours < 24) return `${hours}h ago`;
    const days = Math.floor(hours / 24);
    return `${days}d ago`;
}

export function formatCountdown(secondsRemaining) {
    if (secondsRemaining <= 0) {
        return { expired: true, text: "Expired", days: 0, hours: 0, minutes: 0, seconds: 0 };
    }
    const days = Math.floor(secondsRemaining / 86400);
    const hours = Math.floor((secondsRemaining % 86400) / 3600);
    const minutes = Math.floor((secondsRemaining % 3600) / 60);
    const seconds = secondsRemaining % 60;

    const pad = (n) => String(n).padStart(2, "0");
    let text = "";
    if (days > 0) {
        text = `${days}d ${pad(hours)}h ${pad(minutes)}m ${pad(seconds)}s`;
    } else {
        text = `${pad(hours)}h ${pad(minutes)}m ${pad(seconds)}s`;
    }

    return {
        expired: false,
        text,
        days,
        hours,
        minutes,
        seconds
    };
}

export function shareLink(fileId, key) {
    return `${window.location.origin}/f/${encodeURIComponent(fileId)}#${key}`;
}

export async function copyText(value) {
    try {
        await navigator.clipboard.writeText(value);
        return true;
    } catch (e) {
        const input = document.createElement("input");
        input.value = value;
        document.body.appendChild(input);
        input.select();
        const success = document.execCommand("copy");
        document.body.removeChild(input);
        return success;
    }
}

export function showToast(message, type = "info", duration = 3000) {
    let container = document.getElementById("toast-container");
    if (!container) {
        container = document.createElement("div");
        container.id = "toast-container";
        container.className = "toast-container";
        document.body.appendChild(container);
    }

    const toast = document.createElement("div");
    toast.className = `toast-item toast-${type}`;
    
    let icon = "ℹ️";
    if (type === "success") icon = "✓";
    if (type === "error") icon = "✕";
    if (type === "warning") icon = "⚠️";

    toast.innerHTML = `
        <span class="toast-icon">${icon}</span>
        <span class="toast-message">${message}</span>
    `;

    container.appendChild(toast);

    // Animate in
    requestAnimationFrame(() => {
        toast.classList.add("toast-show");
    });

    setTimeout(() => {
        toast.classList.remove("toast-show");
        toast.classList.add("toast-hide");
        setTimeout(() => toast.remove(), 300);
    }, duration);
}

// Global exposure for non-module compatibility
if (typeof window !== "undefined") {
    window.VaultXSharing = {
        formatBytes,
        formatTime,
        formatRelativeTime,
        formatCountdown,
        shareLink,
        copyText,
        showToast
    };
}
