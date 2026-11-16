// HMAC-SHA-256 signing/verification built on WebCrypto so the exact same code
// runs on Node 20+ and inside a Cloudflare Worker.
//
// PROTOCOL ASSUMPTIONS (PROTOCOL.md §2 and §16.1 — NOT documented publicly,
// confirm at preflight, which is the platform's conformance test):
//   * Algorithm: HMAC-SHA-256. Encoding of the signature header: lowercase hex.
//   * Secret key material: the dashboard "Rotate Secret" value is a 32-byte
//     secret. If AGENT_GAMES_HMAC_SECRET is exactly 64 hex chars we decode it
//     to 32 raw bytes; otherwise we use its UTF-8 bytes. Override with
//     AGENT_GAMES_HMAC_SECRET_FORMAT = "hex" | "utf8" | "base64".
//   If preflight fails with a signature error, flip the format env var first —
//   that is the cheapest knob and the most likely mismatch.

const textEncoder = new TextEncoder();

export function secretToKeyBytes(secret, format) {
  if (typeof secret !== "string" || secret.length === 0) {
    throw new Error("AGENT_GAMES_HMAC_SECRET is empty");
  }
  const fmt =
    format ||
    (/^[0-9a-fA-F]{64}$/.test(secret.trim()) ? "hex" : "utf8");
  const s = secret.trim();
  switch (fmt) {
    case "hex": {
      if (!/^[0-9a-fA-F]+$/.test(s) || s.length % 2 !== 0) {
        throw new Error("HMAC secret format=hex but value is not valid hex");
      }
      const bytes = new Uint8Array(s.length / 2);
      for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(s.slice(2 * i, 2 * i + 2), 16);
      }
      return bytes;
    }
    case "base64": {
      // atob exists in Node 16+ and in Workers.
      const bin = atob(s);
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      return bytes;
    }
    case "utf8":
      return textEncoder.encode(s);
    default:
      throw new Error(`Unknown AGENT_GAMES_HMAC_SECRET_FORMAT: ${fmt}`);
  }
}

export async function importHmacKey(secret, format) {
  const keyBytes = secretToKeyBytes(secret, format);
  return crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
}

function bytesToHex(bytes) {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

function hexToBytes(hex) {
  if (!/^[0-9a-fA-F]*$/.test(hex) || hex.length % 2 !== 0) return null;
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  }
  return bytes;
}

/** Sign raw body bytes; returns the lowercase-hex signature header value. */
export async function signBodyHex(hmacKey, bodyBytes) {
  const sig = await crypto.subtle.sign("HMAC", hmacKey, bodyBytes);
  return bytesToHex(new Uint8Array(sig));
}

/**
 * Verify an inbound x-agent-games-signature header against the RAW body
 * bytes. Uses subtle.verify (constant-time). Returns false on any malformation
 * — callers must fail closed.
 */
export async function verifyBodyHex(hmacKey, headerValue, bodyBytes) {
  if (typeof headerValue !== "string" || headerValue.length === 0) return false;
  const sigBytes = hexToBytes(headerValue.trim());
  if (!sigBytes || sigBytes.length !== 32) return false;
  try {
    return await crypto.subtle.verify("HMAC", hmacKey, sigBytes, bodyBytes);
  } catch {
    return false;
  }
}
