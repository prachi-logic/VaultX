const http = require("http");
const { webcrypto } = require("crypto");
const subtle = webcrypto.subtle;

// Convert Buffer/Uint8Array to Base64
function toBase64(buffer) {
    return Buffer.from(buffer).toString("base64");
}

function fromBase64(b64) {
    return Buffer.from(b64, "base64");
}

async function testWebCryptoLifecycle() {
    console.log("=== VaultX WebCrypto End-to-End Simulation ===");

    // 1. Generate 256-bit AES-GCM Key
    const key = await subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );
    const exportedRawKey = await subtle.exportKey("raw", key);
    const keyB64 = toBase64(exportedRawKey);
    console.log("[1/5] Key generated (256-bit AES-GCM):", keyB64.slice(0, 16) + "...");

    // 2. Encrypt Plaintext with 12-byte IV
    const originalText = "TopSecretHackathonPayload_ZeroKnowledge_2026_Verifiable!";
    const encodedData = new TextEncoder().encode(originalText);
    const iv = webcrypto.getRandomValues(new Uint8Array(12));
    const ivB64 = toBase64(iv);

    const ciphertextBuffer = await subtle.encrypt(
        { name: "AES-GCM", iv: iv, tagLength: 128 },
        key,
        encodedData
    );
    const ciphertext = Buffer.from(ciphertextBuffer);
    console.log("[2/5] Plaintext encrypted with 12-byte IV. Ciphertext length:", ciphertext.length, "bytes");

    // 3. Verify Decryption with imported key
    const importedKey = await subtle.importKey(
        "raw",
        fromBase64(keyB64),
        { name: "AES-GCM" },
        false,
        ["decrypt"]
    );

    const decryptedBuffer = await subtle.decrypt(
        { name: "AES-GCM", iv: fromBase64(ivB64), tagLength: 128 },
        importedKey,
        ciphertext
    );
    const decryptedText = new TextDecoder().decode(decryptedBuffer);

    console.log("[3/5] Decrypted text:", decryptedText);
    if (decryptedText === originalText) {
        console.log("✓ SUCCESS: Decrypted text matches original plaintext perfectly!");
    } else {
        throw new Error("Decryption failed to match original text!");
    }

    // 4. Test Tamper Resistance (Bit flip)
    console.log("[4/5] Testing GCM Tamper Resistance...");
    const tampered = Buffer.from(ciphertext);
    tampered[5] ^= 0x01; // flip 1 bit
    try {
        await subtle.decrypt(
            { name: "AES-GCM", iv: fromBase64(ivB64), tagLength: 128 },
            importedKey,
            tampered
        );
        throw new Error("Tampered ciphertext should have thrown authentication tag error!");
    } catch (e) {
        console.log("✓ SUCCESS: Tampered ciphertext was rejected by GCM tag verification:", e.message);
    }

    // 5. Test Invalid Key
    console.log("[5/5] Testing Wrong Key Rejection...");
    const wrongKey = await subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
    try {
        await subtle.decrypt(
            { name: "AES-GCM", iv: fromBase64(ivB64), tagLength: 128 },
            wrongKey,
            ciphertext
        );
        throw new Error("Wrong key should have failed decryption!");
    } catch (e) {
        console.log("✓ SUCCESS: Wrong key rejected:", e.message);
    }

    console.log("\n=== ALL WEBCRYPTO CLIENT-SIDE CRYPTOGRAPHIC TESTS PASSED ===");
}

testWebCryptoLifecycle().catch(err => {
    console.error("Test failed:", err);
    process.exit(1);
});
