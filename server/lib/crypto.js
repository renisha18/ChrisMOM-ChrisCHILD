import crypto from "crypto";

const IV_LENGTH = 16;

function getKey() {
  const key = process.env.ENCRYPT_KEY; // 32 bytes as 64 hex chars
  if (!key || key.length !== 64) throw new Error("ENCRYPT_KEY missing or invalid");
  return Buffer.from(key, "hex");
}

export function encrypt(text) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv("aes-256-cbc", getKey(), iv);
  let encrypted = cipher.update(String(text), "utf8", "hex");
  encrypted += cipher.final("hex");
  return iv.toString("hex") + ":" + encrypted;
}

export function decrypt(enc) {
  if (!enc) return null;
  const parts = enc.split(":");
  const iv = Buffer.from(parts.shift(), "hex");
  const decipher = crypto.createDecipheriv("aes-256-cbc", getKey(), iv);
  let decrypted = decipher.update(parts.join(":"), "hex", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}
