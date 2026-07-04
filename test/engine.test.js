'use strict';
/**
 * Offline tests of the re-wrap engine and the controller keyfile, against an
 * in-memory fake of the control plane that mimics the server's version check
 * and recipient-consistency check. Run: npm test (plain node, no framework).
 */
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {
  generateIdentityKeyPair,
  encryptSecret,
  decryptSecret,
} = require('@koove/crypto');
const { rewrapToExpected } = require('../lib/engine');
const keyfile = require('../lib/keyfile');

function test(name, fn) {
  return Promise.resolve()
    .then(fn)
    .then(() => console.log('  ✓', name));
}

/** In-memory control plane: same version + consistency semantics as the server. */
function fakeApi({ recipients, credentials }) {
  const store = credentials.map((c, i) => ({ ...c, version: c.version ?? 1, id: `c${i}` }));
  const state = { recipients: [...recipients].sort(), putCalls: 0 };
  return {
    state,
    store,
    async getDiscovery() {
      return { recipients: state.recipients, devices: [], controllerPublicKey: null, recoveryPublicKey: null };
    },
    async getCredentials() {
      return store.map((c) => ({ key: c.key, env: c.env, envelope: c.envelope, version: c.version }));
    },
    async putRewrap(_appId, items) {
      state.putCalls++;
      const expected = new Set(state.recipients);
      const results = [];
      for (const item of items) {
        const wrapKeys = Object.keys(item.envelope.wraps);
        const missing = [...expected].filter((k) => !wrapKeys.includes(k));
        const extra = wrapKeys.filter((k) => !expected.has(k));
        if (missing.length || extra.length) {
          results.push({ key: item.key, env: item.env, status: 'invalid_recipients', missing, extra });
          continue;
        }
        const cred = store.find((c) => c.key === item.key && c.env === item.env);
        if (!cred) {
          results.push({ key: item.key, env: item.env, status: 'not_found' });
          continue;
        }
        if (cred.version !== item.baseVersion) {
          results.push({ key: item.key, env: item.env, status: 'conflict', currentVersion: cred.version });
          continue;
        }
        cred.envelope = item.envelope;
        cred.version += 1;
        results.push({ key: item.key, env: item.env, status: 'rewrapped', version: cred.version });
      }
      return { results, clearedDevices: [], recipients: state.recipients };
    },
  };
}

const noLog = () => {};

async function main() {
  console.log('re-wrap engine');

  const controller = generateIdentityKeyPair();
  const deviceA = generateIdentityKeyPair();
  const deviceB = generateIdentityKeyPair();

  await test('add-device: a new recipient gains access to existing secrets', async () => {
    const api = fakeApi({
      recipients: [controller.publicKey, deviceA.publicKey, deviceB.publicKey], // B just attested
      credentials: [
        { key: 'DB', env: 'dev', envelope: encryptSecret([controller.publicKey, deviceA.publicKey], 's3cret') },
      ],
    });
    const res = await rewrapToExpected({ api, appId: 'a', identity: controller, log: noLog });
    assert.strictEqual(res.converged, true);
    assert.strictEqual(res.rewrapped, 1);
    // B can now decrypt; the value survived the re-wrap untouched.
    assert.strictEqual(decryptSecret(deviceB, api.store[0].envelope), 's3cret');
    assert.strictEqual(decryptSecret(deviceA, api.store[0].envelope), 's3cret');
  });

  await test('HARD kill: the revoked device is removed from every envelope', async () => {
    const api = fakeApi({
      recipients: [controller.publicKey, deviceA.publicKey], // B revoked -> out of discovery
      credentials: [
        { key: 'DB', env: 'dev', envelope: encryptSecret([controller.publicKey, deviceA.publicKey, deviceB.publicKey], 'v1') },
        { key: 'API', env: 'prod', envelope: encryptSecret([controller.publicKey, deviceA.publicKey, deviceB.publicKey], 'v2') },
      ],
    });
    const res = await rewrapToExpected({ api, appId: 'a', identity: controller, log: noLog });
    assert.strictEqual(res.converged, true);
    assert.strictEqual(res.rewrapped, 2);
    for (const cred of api.store) {
      assert.ok(!(deviceB.publicKey in cred.envelope.wraps), 'revoked key must be gone');
      assert.throws(() => decryptSecret(deviceB, cred.envelope)); // not a recipient anymore
    }
    assert.strictEqual(decryptSecret(deviceA, api.store[0].envelope), 'v1');
  });

  await test('idempotent: a second run finds nothing to do', async () => {
    const api = fakeApi({
      recipients: [controller.publicKey, deviceA.publicKey],
      credentials: [
        { key: 'DB', env: 'dev', envelope: encryptSecret([controller.publicKey], 'x') },
      ],
    });
    await rewrapToExpected({ api, appId: 'a', identity: controller, log: noLog });
    const putCallsAfterFirst = api.state.putCalls;
    const second = await rewrapToExpected({ api, appId: 'a', identity: controller, log: noLog });
    assert.strictEqual(second.converged, true);
    assert.strictEqual(second.rewrapped, 0);
    assert.strictEqual(api.state.putCalls, putCallsAfterFirst, 'no uploads on a converged state');
  });

  await test('optimistic concurrency: a conflicting write is retried against fresh state', async () => {
    const api = fakeApi({
      recipients: [controller.publicKey, deviceA.publicKey],
      credentials: [
        { key: 'DB', env: 'dev', envelope: encryptSecret([controller.publicKey], 'x') },
      ],
    });
    // Simulate a concurrent writer bumping the version between read and upload.
    const originalPut = api.putRewrap.bind(api);
    let raced = false;
    api.putRewrap = async (appId, items, by) => {
      if (!raced) {
        raced = true;
        api.store[0].version += 1; // the concurrent write wins the first round
      }
      return originalPut(appId, items, by);
    };
    const res = await rewrapToExpected({ api, appId: 'a', identity: controller, log: noLog });
    assert.strictEqual(res.converged, true);
    assert.ok(res.passes >= 2, 'needs a retry pass after the conflict');
  });

  await test('an envelope the authorizer cannot open is a permanent, reported error', async () => {
    const stranger = generateIdentityKeyPair();
    const api = fakeApi({
      recipients: [controller.publicKey, deviceA.publicKey],
      credentials: [
        { key: 'ORPHAN', env: 'dev', envelope: encryptSecret([stranger.publicKey], 'x') },
      ],
    });
    const res = await rewrapToExpected({ api, appId: 'a', identity: controller, log: noLog });
    assert.strictEqual(res.converged, false);
    assert.strictEqual(res.errors.length, 1);
    assert.match(res.errors[0].reason, /no es destinataria/);
  });

  console.log('controller keyfile');

  await test('save/load roundtrip with the right passphrase', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'koove-keyfile-'));
    const file = path.join(dir, 'controller-test.key');
    const identity = generateIdentityKeyPair();
    keyfile.saveIdentity(file, identity, 'correct horse');
    const loaded = keyfile.loadIdentity(file, 'correct horse');
    assert.deepStrictEqual(loaded, identity);
    assert.strictEqual(keyfile.peekPublicKey(file), identity.publicKey);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  await test('a wrong passphrase is rejected (GCM tag)', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'koove-keyfile-'));
    const file = path.join(dir, 'controller-test.key');
    keyfile.saveIdentity(file, generateIdentityKeyPair(), 'right');
    assert.throws(() => keyfile.loadIdentity(file, 'wrong'), /passphrase incorrecta/);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  await test('refuses to silently overwrite an existing keyfile', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'koove-keyfile-'));
    const file = path.join(dir, 'controller-test.key');
    keyfile.saveIdentity(file, generateIdentityKeyPair(), 'p');
    assert.throws(() => keyfile.saveIdentity(file, generateIdentityKeyPair(), 'p'), /ya existe/);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  console.log('\nAll CLI engine/keyfile tests passed.');
}

main().catch((e) => {
  console.error('✗', e.message);
  process.exit(1);
});
