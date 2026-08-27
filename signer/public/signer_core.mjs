import { BIP39_ENGLISH_WORDS, BIP39_WORDLIST_SHA256 } from "./bip39_english.mjs";

export const PROFILE_ID = "DCT_GOV10_PERSONAL_USE_EPHEMERAL_OFFLINE_WEB_SIGNING_PROFILE_R1";
export const PROFILE_VERSION = "1.0.0";
export const CLASSIFICATION = "SYNTHETIC_TEST_ONLY_NOT_OWNER_KEY_NOT_OWNER_ISSUANCE";
export const DCT_SIGNATURE_DOMAIN = "DCT_STAGE3_V2_OWNER_ISSUANCE_DECISION_SIGNATURE_R1";
export const SYNTHETIC_DECISION_DIGEST = "854aa9befe1104bbe4f9d9c2758ce619fb4c645889e800beba022d18710189d5";
export const SYNTHETIC_MNEMONIC = `${"abandon ".repeat(23)}art`.trim();
export const EXPECTED_PUBLIC_KEY_HEX = "7afa7190d9f5daeaa45d9650ed3ce7c0973bb0e35f7361bf858389a8cf1c3f3c";
export const EXPECTED_PUBLIC_KEY_SHA256 = "896e7f2695be451ed8610df57069eee7b11836b03b2947d9ae913022a6c6da8f";
export const EXPECTED_SIGNATURE_BASE64URL = "KAp74aMfrCBI7XY8CE3tZ6eDVZW0g7sKM-zeeZZB4G6WPJznA9veswu3maxvmnXmes6SH3KVyBQxrBpqPJlhAg";

const textEncoder = new TextEncoder();
const decisionPattern = /^[0-9a-f]{64}$/;
const hexPattern = /^[0-9a-f]+$/;
const wordIndex = new Map(BIP39_ENGLISH_WORDS.map((word, index) => [word, index]));

export class PwebQualificationError extends Error {
  constructor(code) {
    super(code);
    this.name = "PwebQualificationError";
    this.code = code;
  }
}

function requireWebCrypto() {
  if (typeof window !== "undefined" && globalThis.isSecureContext !== true) {
    throw new PwebQualificationError("SECURE_CONTEXT_REQUIRED");
  }
  if (!globalThis.crypto || !globalThis.crypto.subtle) {
    throw new PwebQualificationError("WEBCRYPTO_SUBTLE_UNAVAILABLE");
  }
  return globalThis.crypto.subtle;
}

export function bytesToHex(bytes) {
  return Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");
}

export function hexToBytes(value) {
  if (typeof value !== "string" || value.length % 2 !== 0 || !hexPattern.test(value)) {
    throw new PwebQualificationError("HEX_FORMAT_MISMATCH");
  }
  return Uint8Array.from(value.match(/../g), (part) => Number.parseInt(part, 16));
}

export function concatBytes(...arrays) {
  const total = arrays.reduce((sum, item) => sum + item.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const item of arrays) {
    result.set(item, offset);
    offset += item.length;
  }
  return result;
}

export async function digest(name, bytes) {
  const result = await requireWebCrypto().digest(name, bytes);
  return new Uint8Array(result);
}

export async function sha256Hex(bytes) {
  return bytesToHex(await digest("SHA-256", bytes));
}

async function hmacSha512(key, data) {
  const subtle = requireWebCrypto();
  const cryptoKey = await subtle.importKey(
    "raw",
    key,
    { name: "HMAC", hash: "SHA-512" },
    false,
    ["sign"],
  );
  return new Uint8Array(await subtle.sign("HMAC", cryptoKey, data));
}

function bytesToBits(bytes) {
  return Array.from(bytes, (value) => value.toString(2).padStart(8, "0")).join("");
}

export async function validateMnemonic(mnemonic) {
  if (typeof mnemonic !== "string") {
    throw new PwebQualificationError("MNEMONIC_TYPE_MISMATCH");
  }
  if (!/^[a-z]+(?: [a-z]+){23}$/.test(mnemonic)) {
    throw new PwebQualificationError("MNEMONIC_EXACT_24_WORD_ASCII_FORMAT_MISMATCH");
  }
  const parts = mnemonic.split(" ");
  const indices = parts.map((word) => wordIndex.get(word));
  if (indices.some((value) => value === undefined)) {
    throw new PwebQualificationError("MNEMONIC_WORD_NOT_IN_PINNED_WORDLIST");
  }
  const bits = indices.map((value) => value.toString(2).padStart(11, "0")).join("");
  const entropyBits = bits.slice(0, 256);
  const checksumBits = bits.slice(256);
  const entropy = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) {
    entropy[i] = Number.parseInt(entropyBits.slice(i * 8, i * 8 + 8), 2);
  }
  const checksum = bytesToBits(await digest("SHA-256", entropy)).slice(0, 8);
  if (checksum !== checksumBits) {
    entropy.fill(0);
    throw new PwebQualificationError("MNEMONIC_CHECKSUM_MISMATCH");
  }
  return entropy;
}

export async function bip39SeedOptionA(mnemonic) {
  const entropy = await validateMnemonic(mnemonic);
  entropy.fill(0);
  const normalizedMnemonic = mnemonic.normalize("NFKD");
  const passwordBytes = textEncoder.encode(normalizedMnemonic);
  const saltBytes = textEncoder.encode("mnemonic");
  const subtle = requireWebCrypto();
  const baseKey = await subtle.importKey("raw", passwordBytes, "PBKDF2", false, ["deriveBits"]);
  try {
    const bits = await subtle.deriveBits(
      { name: "PBKDF2", hash: "SHA-512", salt: saltBytes, iterations: 2048 },
      baseKey,
      512,
    );
    return new Uint8Array(bits);
  } finally {
    passwordBytes.fill(0);
    saltBytes.fill(0);
  }
}

export async function bip39SeedStandardsTestOnly(mnemonic, passphrase) {
  if (typeof mnemonic !== "string" || typeof passphrase !== "string") {
    throw new PwebQualificationError("BIP39_TEST_VECTOR_INPUT_TYPE_MISMATCH");
  }
  const subtle = requireWebCrypto();
  const passwordBytes = textEncoder.encode(mnemonic.normalize("NFKD"));
  const saltBytes = textEncoder.encode(`mnemonic${passphrase.normalize("NFKD")}`);
  const baseKey = await subtle.importKey("raw", passwordBytes, "PBKDF2", false, ["deriveBits"]);
  try {
    return new Uint8Array(await subtle.deriveBits(
      { name: "PBKDF2", hash: "SHA-512", salt: saltBytes, iterations: 2048 },
      baseKey,
      512,
    ));
  } finally {
    passwordBytes.fill(0);
    saltBytes.fill(0);
  }
}

export async function slip10Ed25519Master(seed) {
  if (!(seed instanceof Uint8Array) || seed.length < 16) {
    throw new PwebQualificationError("SLIP10_SEED_TYPE_OR_LENGTH_MISMATCH");
  }
  const result = await hmacSha512(textEncoder.encode("ed25519 seed"), seed);
  return {
    privateSeed: result.slice(0, 32),
    chainCode: result.slice(32),
  };
}

const FIELD_P = (1n << 255n) - 19n;
function mod(value) {
  const result = value % FIELD_P;
  return result >= 0n ? result : result + FIELD_P;
}
function powMod(base, exponent) {
  let x = mod(base);
  let n = exponent;
  let result = 1n;
  while (n > 0n) {
    if (n & 1n) result = mod(result * x);
    x = mod(x * x);
    n >>= 1n;
  }
  return result;
}
function inverse(value) {
  return powMod(value, FIELD_P - 2n);
}
const EDWARDS_D = mod(-121665n * inverse(121666n));
const SQRT_M1 = powMod(2n, (FIELD_P - 1n) / 4n);

function recoverX(y) {
  const yy = mod(y * y);
  const xSquared = mod((yy - 1n) * inverse(EDWARDS_D * yy + 1n));
  let x = powMod(xSquared, (FIELD_P + 3n) / 8n);
  if (mod(x * x - xSquared) !== 0n) x = mod(x * SQRT_M1);
  if (mod(x * x - xSquared) !== 0n) {
    throw new PwebQualificationError("ED25519_BASE_POINT_RECOVERY_FAILURE");
  }
  if (x & 1n) x = FIELD_P - x;
  return x;
}

const BASE_Y = mod(4n * inverse(5n));
const BASE_POINT = Object.freeze({ x: recoverX(BASE_Y), y: BASE_Y });
const IDENTITY_POINT = Object.freeze({ x: 0n, y: 1n });

function pointAdd(left, right) {
  const product = mod(EDWARDS_D * left.x * right.x * left.y * right.y);
  return {
    x: mod((left.x * right.y + left.y * right.x) * inverse(1n + product)),
    y: mod((left.y * right.y + left.x * right.x) * inverse(1n - product)),
  };
}

function scalarMultiplyBase(scalar) {
  let value = scalar;
  let addend = BASE_POINT;
  let result = IDENTITY_POINT;
  while (value > 0n) {
    if (value & 1n) result = pointAdd(result, addend);
    addend = pointAdd(addend, addend);
    value >>= 1n;
  }
  return result;
}

function littleEndianToBigInt(bytes) {
  let value = 0n;
  for (let i = bytes.length - 1; i >= 0; i -= 1) {
    value = (value << 8n) | BigInt(bytes[i]);
  }
  return value;
}

function bigIntToLittleEndian(value, length) {
  let remaining = value;
  const output = new Uint8Array(length);
  for (let i = 0; i < length; i += 1) {
    output[i] = Number(remaining & 255n);
    remaining >>= 8n;
  }
  return output;
}

export async function ed25519PublicFromSeed(privateSeed) {
  if (!(privateSeed instanceof Uint8Array) || privateSeed.length !== 32) {
    throw new PwebQualificationError("ED25519_PRIVATE_SEED_LENGTH_MISMATCH");
  }
  const expanded = await digest("SHA-512", privateSeed);
  expanded[0] &= 248;
  expanded[31] &= 63;
  expanded[31] |= 64;
  const scalar = littleEndianToBigInt(expanded.slice(0, 32));
  const publicPoint = scalarMultiplyBase(scalar);
  const encoded = bigIntToLittleEndian(publicPoint.y, 32);
  encoded[31] |= Number((publicPoint.x & 1n) << 7n);
  expanded.fill(0);
  return encoded;
}

function privatePkcs8(privateSeed) {
  const prefix = hexToBytes("302e020100300506032b657004220420");
  return concatBytes(prefix, privateSeed);
}

export async function signEd25519(privateSeed, message) {
  const subtle = requireWebCrypto();
  const pkcs8 = privatePkcs8(privateSeed);
  try {
    const key = await subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, false, ["sign"]);
    return new Uint8Array(await subtle.sign("Ed25519", key, message));
  } catch (error) {
    throw new PwebQualificationError(`WEBCRYPTO_ED25519_IMPORT_OR_SIGN_FAILURE:${error?.name || "ERROR"}`);
  } finally {
    pkcs8.fill(0);
  }
}

export async function verifyEd25519(publicKey, signature, message) {
  const subtle = requireWebCrypto();
  try {
    const key = await subtle.importKey("raw", publicKey, { name: "Ed25519" }, false, ["verify"]);
    return await subtle.verify("Ed25519", key, signature, message);
  } catch (error) {
    throw new PwebQualificationError(`WEBCRYPTO_ED25519_VERIFY_FAILURE:${error?.name || "ERROR"}`);
  }
}

export function dctSigningPreimage(decisionDigest) {
  if (typeof decisionDigest !== "string" || !decisionPattern.test(decisionDigest)) {
    throw new PwebQualificationError("DECISION_DIGEST_FORMAT_MISMATCH");
  }
  return concatBytes(
    textEncoder.encode(DCT_SIGNATURE_DOMAIN),
    Uint8Array.of(0),
    textEncoder.encode(decisionDigest),
  );
}

export function canonicalBase64url(bytes) {
  let binary = "";
  for (const value of bytes) binary += String.fromCharCode(value);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

export async function runtimeCapabilitySelfTest() {
  const secret = hexToBytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
  const expectedPublic = hexToBytes("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
  const expectedSignature = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";
  const empty = new Uint8Array();
  try {
    const publicKey = await ed25519PublicFromSeed(secret);
    if (bytesToHex(publicKey) !== bytesToHex(expectedPublic)) {
      throw new PwebQualificationError("RFC8032_PUBLIC_KEY_KNOWN_ANSWER_MISMATCH");
    }
    const signature = await signEd25519(secret, empty);
    if (bytesToHex(signature) !== expectedSignature) {
      throw new PwebQualificationError("RFC8032_SIGNATURE_KNOWN_ANSWER_MISMATCH");
    }
    if (!(await verifyEd25519(expectedPublic, signature, empty))) {
      throw new PwebQualificationError("RFC8032_WEBCRYPTO_VERIFY_FAILURE");
    }
    const wordlistHash = await sha256Hex(textEncoder.encode(`${BIP39_ENGLISH_WORDS.join("\n")}\n`));
    if (wordlistHash !== BIP39_WORDLIST_SHA256) {
      throw new PwebQualificationError("PINNED_WORDLIST_HASH_MISMATCH");
    }
    return {
      status: "PASS_RUNTIME_CAPABILITY_SYNTHETIC_ONLY",
      webcrypto_ed25519: true,
      rfc8032_vector: true,
      pinned_wordlist: true,
      authority_granted: false,
      real_use_available: false,
    };
  } finally {
    secret.fill(0);
    expectedPublic.fill(0);
  }
}

export async function recoverAndSignSyntheticTestOnly({ copyLabel, mnemonic, decisionDigest }) {
  if (!['COPY_A', 'COPY_B'].includes(copyLabel)) {
    throw new PwebQualificationError("SYNTHETIC_COPY_LABEL_MISMATCH");
  }
  if (mnemonic !== SYNTHETIC_MNEMONIC || decisionDigest !== SYNTHETIC_DECISION_DIGEST) {
    throw new PwebQualificationError("REAL_OR_UNAPPROVED_INPUT_FORBIDDEN_IN_SYNTHETIC_BUILD");
  }
  const seed = await bip39SeedOptionA(mnemonic);
  let privateSeed;
  let chainCode;
  try {
    ({ privateSeed, chainCode } = await slip10Ed25519Master(seed));
    const publicKey = await ed25519PublicFromSeed(privateSeed);
    const publicKeyHex = bytesToHex(publicKey);
    const publicKeySha256 = await sha256Hex(publicKey);
    if (publicKeyHex !== EXPECTED_PUBLIC_KEY_HEX || publicKeySha256 !== EXPECTED_PUBLIC_KEY_SHA256) {
      throw new PwebQualificationError("RECOVERED_PUBLIC_KEY_KNOWN_ANSWER_MISMATCH");
    }
    const preimage = dctSigningPreimage(decisionDigest);
    const signature = await signEd25519(privateSeed, preimage);
    if (!(await verifyEd25519(publicKey, signature, preimage))) {
      throw new PwebQualificationError("DCT_SIGNATURE_VERIFICATION_FAILURE");
    }
    const signatureBase64url = canonicalBase64url(signature);
    if (signatureBase64url !== EXPECTED_SIGNATURE_BASE64URL) {
      throw new PwebQualificationError("DCT_SIGNATURE_KNOWN_ANSWER_MISMATCH");
    }
    return Object.freeze({
      status: "PASS_SYNTHETIC_RECOVERY_AND_SIGNATURE_ZERO_AUTHORITY",
      copy_label: copyLabel,
      profile_id: PROFILE_ID,
      classification: CLASSIFICATION,
      public_key_hex: publicKeyHex,
      public_key_sha256: publicKeySha256,
      public_key_base64url: canonicalBase64url(publicKey),
      decision_record_sha256: decisionDigest,
      preimage_sha256: await sha256Hex(preimage),
      signature_base64url: signatureBase64url,
      authority_granted: false,
      owner_key_generated: false,
      trust_anchor_established: false,
      gov10_granted: false,
      real_use_available: false,
    });
  } finally {
    seed.fill(0);
    if (privateSeed) privateSeed.fill(0);
    if (chainCode) chainCode.fill(0);
  }
}

export function realOwnerSigningUnavailable() {
  throw new PwebQualificationError("REAL_OWNER_SIGNING_NOT_AUTHORIZED_OR_AVAILABLE_IN_R1_SYNTHETIC_BUILD");
}
