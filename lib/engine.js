'use strict';
/**
 * The re-wrap engine (task6 §4, §8b, §9): drive every stored envelope's
 * recipient set to EXACTLY the app's expected set (usable devices ∪ controller
 * ∪ recovery, as served by discovery). One engine covers all three lifecycle
 * operations — add-device, HARD kill, and controller/recovery rotation — since
 * each is just "the expected set changed; make the envelopes match".
 *
 * Properties the design demands:
 *  - Client-side crypto only: the DEK is opened with the authorizing identity
 *    (controller or recovery) and re-sealed locally; the server just stores.
 *  - Idempotent + resumable: each pass re-reads server state and skips
 *    envelopes that already match; re-running after a crash converges.
 *  - Add-before-remove, per envelope: wraps are REPLACED atomically in one
 *    upsert, so every stored version always contains a valid authorizer wrap —
 *    there is no window where an envelope is readable by nobody.
 *  - Optimistic concurrency: uploads carry the version each envelope was read
 *    at; a concurrent write turns into a per-item conflict and the next pass
 *    retries against fresh state.
 */
const { openKey, sealKey } = require('@koove/crypto');

const BATCH_LIMIT = 500;

function sameSet(a, b) {
  return a.size === b.size && [...a].every((k) => b.has(k));
}

/**
 * Run re-wrap passes until convergence.
 *
 * @param {object} opts
 * @param {object} opts.api        client from createApi()
 * @param {string} opts.appId
 * @param {object} opts.identity   authorizing IdentityKeyPair (controller or recovery)
 * @param {'controller'|'recovery'} [opts.authorizedBy]
 * @param {(msg: string) => void} [opts.log]
 * @param {number} [opts.maxPasses]
 * @returns {{ converged: boolean, rewrapped: number, clearedDevices: string[],
 *            errors: {key: string, env: string, reason: string}[], passes: number }}
 */
async function rewrapToExpected({
  api,
  appId,
  identity,
  authorizedBy = 'controller',
  log = () => {},
  maxPasses = 5,
}) {
  const permanent = new Map(); // "key env" -> {key, env, reason}
  const clearedDevices = new Set();
  let rewrapped = 0;

  for (let pass = 1; pass <= maxPasses; pass++) {
    // Fresh server state every pass: expected set AND envelope versions.
    const discovery = await api.getDiscovery(appId);
    const expected = new Set(discovery.recipients);
    if (expected.size === 0) {
      return {
        converged: false,
        rewrapped,
        clearedDevices: [...clearedDevices],
        errors: [{ key: '*', env: '*', reason: 'el recipient set de la app está vacío' }],
        passes: pass,
      };
    }

    const credentials = await api.getCredentials(appId);
    const items = [];
    for (const cred of credentials) {
      const id = `${cred.key} ${cred.env}`;
      if (permanent.has(id)) continue;
      const envelope = cred.envelope;
      if (!envelope || typeof envelope !== 'object' || !envelope.wraps) {
        permanent.set(id, { key: cred.key, env: cred.env, reason: 'envelope malformado' });
        continue;
      }
      if (sameSet(new Set(Object.keys(envelope.wraps)), expected)) continue; // already converged

      const myWrap = envelope.wraps[identity.publicKey];
      if (!myWrap) {
        permanent.set(id, {
          key: cred.key,
          env: cred.env,
          reason: 'la identidad autorizadora no es destinataria de este secreto',
        });
        continue;
      }

      // Open the DEK locally and re-seal it for the exact expected set,
      // reusing existing wraps for recipients that stay.
      const dek = openKey(identity.secretKey, myWrap);
      const wraps = {};
      for (const pk of expected) {
        wraps[pk] = envelope.wraps[pk] ?? sealKey(pk, dek);
      }
      items.push({
        key: cred.key,
        env: cred.env,
        envelope: { ...envelope, wraps },
        baseVersion: cred.version,
      });
    }

    if (items.length === 0) {
      return {
        // Everything reachable matches the expected set; converged only if no
        // envelope was left behind by a permanent error.
        converged: permanent.size === 0,
        rewrapped,
        clearedDevices: [...clearedDevices],
        errors: [...permanent.values()],
        passes: pass,
      };
    }

    log(`   Pasada ${pass}: re-envolviendo ${items.length} secreto(s)...`);
    let passRewrapped = 0;
    let passTransient = 0;
    for (let i = 0; i < items.length; i += BATCH_LIMIT) {
      const res = await api.putRewrap(appId, items.slice(i, i + BATCH_LIMIT), authorizedBy);
      for (const r of res.results) {
        if (r.status === 'rewrapped') {
          passRewrapped++;
        } else if (r.status === 'invalid' ) {
          permanent.set(`${r.key} ${r.env}`, { key: r.key, env: r.env, reason: r.reason });
        } else {
          // 'conflict' | 'not_found' | 'invalid_recipients': transient — the
          // next pass re-reads fresh versions / the fresh expected set.
          passTransient++;
        }
      }
      for (const d of res.clearedDevices ?? []) clearedDevices.add(d);
    }
    rewrapped += passRewrapped;

    if (passRewrapped === 0 && passTransient === 0) {
      // A full pass moved nothing and nothing is retryable: whatever is left
      // failed permanently and cannot make progress.
      return {
        converged: false,
        rewrapped,
        clearedDevices: [...clearedDevices],
        errors: [...permanent.values()],
        passes: pass,
      };
    }
  }

  return {
    converged: false,
    rewrapped,
    clearedDevices: [...clearedDevices],
    errors: [
      ...permanent.values(),
      { key: '*', env: '*', reason: `sin converger tras ${maxPasses} pasadas (¿escrituras concurrentes?); re-ejecuta` },
    ],
    passes: maxPasses,
  };
}

module.exports = { rewrapToExpected };
