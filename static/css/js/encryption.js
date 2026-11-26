/**
 * VaultX - Zero-Knowledge Client-Side Encryption
 * Uses Web Crypto API (AES-256-GCM)
 */

window.VaultXEncryption = {

    toBase64: function (buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = "";
        const len = bytes.byteLength;
        const chunkSize = 8192;
        for (let i = 0; i < len; i += chunkSize) {
            const chunk = bytes.subarray(i, Math.min(i + chunkSize, len));
            binary += String.fromCharCode.apply(null, chunk);
        }
        return btoa(binary);
    },

    fromBase64: function (text) {
        if (!text) {
            throw new Error("Decryption key or IV is missing.");
        }
        // Normalize URL-encoded characters and spaces
        let cleaned = decodeURIComponent(text).trim();
        // Convert base64url to standard base64 if needed
        cleaned = cleaned.replace(/-/g, "+").replace(/_/g, "/");
        while (cleaned.length % 4 !== 0) {
            cleaned += "=";
        }

        try {
            const binary = atob(cleaned);
            const bytes = new Uint8Array(binary.length);
            for (let i = 0; i < binary.length; i++) {
                bytes[i] = binary.charCodeAt(i);
            }
            return bytes;
        } catch (e) {
            throw new Error("Invalid encryption key format in share link.");
        }
    },

    encryptFile: async function (file) {
        if (!window.crypto || !crypto.subtle) {
            throw new Error("Web Crypto API is not available. Please use localhost or HTTPS.");
        }

        // Generate high-entropy 256-bit AES-GCM key
        const key = await crypto.subtle.generateKey(
            {
                name: "AES-GCM",
                length: 256
            },
            true,
            ["encrypt", "decrypt"]
        );

        // 96-bit (12 bytes) Initialization Vector for AES-GCM
        const iv = crypto.getRandomValues(new Uint8Array(12));

        const fileData = await file.arrayBuffer();

        const encryptedData = await crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv: iv,
                tagLength: 128
            },
            key,
            fileData
        );

        const rawKey = await crypto.subtle.exportKey("raw", key);

        return {
            encryptedData: encryptedData,
            iv: this.toBase64(iv),
            key: this.toBase64(rawKey)
        };
    },

    decryptFile: async function (encryptedData, ivText, keyText) {
        if (!window.crypto || !crypto.subtle) {
            throw new Error("Web Crypto API is not available. Please use localhost or HTTPS.");
        }

        const iv = this.fromBase64(ivText);
        const rawKey = this.fromBase64(keyText);

        const key = await crypto.subtle.importKey(
            "raw",
            rawKey,
            {
                name: "AES-GCM"
            },
            false,
            ["decrypt"]
        );

        return await crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: iv,
                tagLength: 128
            },
            key,
            encryptedData
        );
    }
};

console.log("VaultX WebCrypto AES-256 Engine Initialized");
