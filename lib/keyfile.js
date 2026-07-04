'use strict';
/**
 * ControllerKeyProvider, MVP implementation (task6 §7a): the controller's
 * X25519 identity in a local keyfile encrypted with a passphrase.
 *
 *   key = scrypt(passphrase, salt)   ->   AES-256-GCM(identity JSON)
 *
 * The provider surface is deliberately tiny — `loadIdentity` / `saveIdentity`
 * — so a KMS/HSM-backed implementation can replace the keyfile behind the same
 * call sites without rewriting the commands (prod/CI path; split/threshold is
 * deferred but fits the same seam).
 *
 * The private key exists in plaintext only in process memory while a command
 * runs; it never reaches the server (zero-knowledge) and never touches disk
 * unencrypted.
 */
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');

const KEYS_DIR = path.join(os.homedir(), '.koove-secrets', 'keys');

const SCRYPT = { N: 2 ** 15, r: 8, p: 1, maxmem: 128 * 1024 * 1024 };

/** Path of the controller keyfile for an app. `suffix` distinguishes staged
 * files during rotation ('.new') and archived ones ('.old-<ts>'). */
function controllerKeyPath(appId, suffix = '') {
  return path.join(KEYS_DIR, `controller-${appId}.key${suffix}`);
}

function encryptIdentity(identity, passphrase) {
  const salt = crypto.randomBytes(16);
  const key = crypto.scryptSync(passphrase, salt, 32, SCRYPT);
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
  const ct = Buffer.concat([cipher.update(JSON.stringify(identity), 'utf8'), cipher.final(), cipher.getAuthTag()]);
  return {
    v: 1,
    kdf: 'scrypt',
    params: { N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p },
    salt: salt.toString('base64'),
    nonce: nonce.toString('base64'),
    ct: ct.toString('base64'),
    // Public, non-secret hint so tooling can match keyfile <-> server record
    // without decrypting.
    publicKey: identity.publicKey,
  };
}

function decryptIdentity(fileJson, passphrase) {
  if (fileJson.v !== 1 || fileJson.kdf !== 'scrypt') {
    throw new Error('unsupported keyfile format');
  }
  const salt = Buffer.from(fileJson.salt, 'base64');
  const params = { ...SCRYPT, ...fileJson.params };
  const key = crypto.scryptSync(passphrase, salt, 32, { ...params, maxmem: SCRYPT.maxmem });
  const raw = Buffer.from(fileJson.ct, 'base64');
  const ct = raw.subarray(0, raw.length - 16);
  const tag = raw.subarray(raw.length - 16);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(fileJson.nonce, 'base64'));
  decipher.setAuthTag(tag);
  let pt;
  try {
    pt = Buffer.concat([decipher.update(ct), decipher.final()]);
  } catch {
    throw new Error('passphrase incorrecta o keyfile corrupto');
  }
  return JSON.parse(pt.toString('utf8'));
}

/** Persist an identity, encrypted. Refuses to overwrite unless told to. */
function saveIdentity(filePath, identity, passphrase, { overwrite = false } = {}) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
  if (!overwrite && fs.existsSync(filePath)) {
    throw new Error(`ya existe un keyfile en ${filePath}`);
  }
  fs.writeFileSync(filePath, JSON.stringify(encryptIdentity(identity, passphrase), null, 2), { mode: 0o600 });
}

/** Load and decrypt an identity keyfile. */
function loadIdentity(filePath, passphrase) {
  if (!fs.existsSync(filePath)) {
    throw new Error(`no existe el keyfile ${filePath}`);
  }
  return decryptIdentity(JSON.parse(fs.readFileSync(filePath, 'utf8')), passphrase);
}

/** Read only the public-key hint of a keyfile (no passphrase needed). */
function peekPublicKey(filePath) {
  if (!fs.existsSync(filePath)) return null;
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8')).publicKey ?? null;
  } catch {
    return null;
  }
}

module.exports = {
  KEYS_DIR,
  controllerKeyPath,
  encryptIdentity,
  decryptIdentity,
  saveIdentity,
  loadIdentity,
  peekPublicKey,
};
