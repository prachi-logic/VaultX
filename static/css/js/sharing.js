export function formatBytes(bytes) {
    if (!bytes || bytes === 0) return "0 Bytes";
    const k = 1024;
    const sizes = ["Bytes", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
}

export function formatTime(unixSeconds) {
    if (!unixSeconds) return "N/A";
    return new Date(unixSeconds * 1000).toLocaleString();
}

export function shareLink(fileId, key) {
    return `${window.location.origin}/f/${encodeURIComponent(fileId)}#${key}`;
}

export async function copyText(value) {
    await navigator.clipboard.writeText(value);
}
