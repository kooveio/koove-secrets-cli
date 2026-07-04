#!/usr/bin/env node
'use strict';
/**
 * Koove secrets CLI — zero-knowledge writer + controller tooling.
 *
 * The CLI plays two roles (task6):
 *  - WRITER: `set` encrypts locally for the app's recipient set (attested
 *    devices ∪ controller ∪ recovery, from discovery) and uploads ciphertext
 *    only. The server never sees a plaintext value.
 *  - CONTROLLER: holds the app's controller identity (encrypted keyfile) and
 *    drives every re-wrap — add-device (`device approve`), HARD kill
 *    (`device revoke`), rotation (`controller rotate`, `recovery rotate`) —
 *    plus the break-glass `recover` flow from the one-time BIP39 code.
 *
 * Zero-knowledge invariant: private keys live here (keyfile / re-derived
 * code), NEVER on the server. The server stores envelopes, gates recipients,
 * and verifies recipient-set consistency — it cannot read or re-wrap.
 */
const { program } = require('commander');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const {
  encryptSecret,
  decryptSecret,
  generateIdentityKeyPair,
  generateRecoveryCode,
  deriveRecoveryIdentity,
} = require('@koove/crypto');

const { createApi } = require('../lib/api');
const { rewrapToExpected } = require('../lib/engine');
const keyfile = require('../lib/keyfile');
const { ask, askHidden, askPassphrase } = require('../lib/prompt');

// ----- Config ----- //
const CONFIG_DIR = path.join(os.homedir(), '.koove-secrets');
const CONFIG_FILE = path.join(CONFIG_DIR, 'config.json');

function loadConfig() {
  if (fs.existsSync(CONFIG_FILE)) {
    return JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
  }
  return {};
}

function saveConfig(config) {
  fs.mkdirSync(CONFIG_DIR, { recursive: true });
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2));
}

// ----- Shared helpers ----- //

function fail(message) {
  console.error(`❌ ${message}`);
  process.exit(1);
}

function apiOrExit() {
  try {
    return createApi(loadConfig());
  } catch (e) {
    return fail(e.message);
  }
}

function httpError(error) {
  const data = error.response?.data;
  return typeof data === 'string' ? data : data ? JSON.stringify(data) : error.message;
}

/** Load the app's controller identity from its encrypted keyfile. */
async function loadController(appId) {
  const filePath = keyfile.controllerKeyPath(appId);
  if (!fs.existsSync(filePath)) {
    fail(
      `No hay keyfile de controller para esta app (${filePath}).\n` +
        '   Ejecuta `koove-secrets app init` primero, o usa `recover rewrap` si lo perdiste.',
    );
  }
  const passphrase = await askPassphrase('Passphrase del controller');
  return keyfile.loadIdentity(filePath, passphrase);
}

/** Run the re-wrap engine and report the outcome. Exits non-zero on failure. */
async function runEngine(api, appId, identity, authorizedBy) {
  const result = await rewrapToExpected({
    api,
    appId,
    identity,
    authorizedBy,
    log: (m) => console.log(m),
  });
  for (const err of result.errors) {
    console.error(`   ⚠️ ${err.key} (${err.env}): ${err.reason}`);
  }
  if (!result.converged) {
    fail('El re-wrap no convergió. Es idempotente: corrige la causa y re-ejecuta.');
  }
  console.log(`✅ Re-wrap completo: ${result.rewrapped} secreto(s) re-envuelto(s) en ${result.passes} pasada(s).`);
  if (result.clearedDevices.length > 0) {
    console.log(`   Dispositivos al día: ${result.clearedDevices.join(', ')}`);
  }
  return result;
}

function printMnemonicOnce(mnemonic, title) {
  const words = mnemonic.split(' ');
  console.log(`\n🔑 ${title}`);
  console.log('   Se muestra UNA sola vez y no se almacena en ningún sitio.');
  console.log('   Sin él (y sin dispositivos), los secretos son IRRECUPERABLES.\n');
  for (let i = 0; i < words.length; i += 6) {
    console.log(
      '   ' +
        words
          .slice(i, i + 6)
          .map((w, j) => `${String(i + j + 1).padStart(2)}. ${w}`)
          .join('  '),
    );
  }
  console.log();
}

async function confirmSaved() {
  if (!process.stdin.isTTY) return;
  const answer = await ask('¿Has guardado el código en un lugar seguro? (escribe "si"): ');
  if (answer.trim().toLowerCase() !== 'si' && answer.trim().toLowerCase() !== 'sí') {
    fail('Cancela y vuelve a empezar cuando puedas guardarlo.');
  }
}

// ----- Program ----- //

program
  .name('koove-secrets')
  .description('CLI zero-knowledge de Koove: escritor de secretos + tooling controller')
  .version('1.1.0');

program
  .command('test')
  .description('Verifica que la CLI funcione')
  .action(() => {
    console.log('✅ ¡CLI operativa!');
  });

program
  .command('config')
  .description('Configura la CLI')
  .option('--api-url <url>', 'URL de la API')
  .option('--app-token <token>', 'Token de la aplicación')
  .action((options) => {
    const config = loadConfig();
    if (options.apiUrl) config.apiUrl = options.apiUrl;
    if (options.appToken) config.appToken = options.appToken;
    saveConfig(config);
    console.log('✅ Configuración guardada en:', CONFIG_FILE);
    console.log('API URL:', config.apiUrl || '(no configurada)');
    console.log('App Token:', config.appToken ? '***' + config.appToken.slice(-4) : '(no configurado)');
  });

// ----- App bootstrap ----- //

program
  .command('app-init')
  .description('Inicializa controller + recovery de la app (hazlo ANTES del primer secreto)')
  .option('--no-recovery', 'opt-out del recovery code (los secretos serán irrecuperables sin dispositivos)')
  .action(async (options) => {
    try {
      const api = apiOrExit();
      const app = await api.getApp();
      const discovery = await api.getDiscovery(app.id);
      const livePath = keyfile.controllerKeyPath(app.id);

      if (discovery.controllerPublicKey) {
        fail('La app ya tiene controller registrado. Usa `controller-rotate` para cambiarlo.');
      }

      // Controller identity: reuse a keyfile left by a previous interrupted
      // init (crash between save and register), otherwise generate fresh.
      let controller;
      if (fs.existsSync(livePath)) {
        console.log('♻️  Encontrado keyfile de un init interrumpido; reutilizándolo.');
        const passphrase = await askPassphrase('Passphrase del controller');
        controller = keyfile.loadIdentity(livePath, passphrase);
      } else {
        controller = generateIdentityKeyPair();
        const passphrase = await askPassphrase('Nueva passphrase del controller', { confirm: true });
        keyfile.saveIdentity(livePath, controller, passphrase);
        console.log(`🔐 Controller keyfile creado: ${livePath}`);
      }

      // Recovery: 24-word code, shown once, never stored (unless opted out).
      const body = { controllerPublicKey: controller.publicKey };
      let mnemonic = null;
      if (options.recovery === false) {
        body.recoveryPublicKey = null;
        console.log('⚠️  Recovery DESACTIVADO por elección: sin dispositivos ni controller, no hay vuelta atrás.');
      } else {
        mnemonic = generateRecoveryCode();
        body.recoveryPublicKey = deriveRecoveryIdentity(mnemonic).publicKey;
      }

      await api.patchRecipients(app.id, body);
      console.log(`✅ Recipients registrados para "${app.name}" (${app.id}).`);

      if (mnemonic) {
        printMnemonicOnce(mnemonic, 'CÓDIGO DE RECUPERACIÓN (24 palabras BIP39)');
        await confirmSaved();
      }

      const credentials = await api.getCredentials(app.id);
      if (credentials.length > 0) {
        console.log(
          `⚠️  La app ya tiene ${credentials.length} secreto(s) escritos ANTES de este init:\n` +
            '   no incluyen al controller/recovery y este no puede re-envolverlos (no es\n' +
            '   destinatario). Re-ejecuta `set` para cada uno y quedarán cubiertos.',
        );
      }
    } catch (error) {
      fail(httpError(error));
    }
  });

// ----- Writer ----- //

program
  .command('set <key> <value>')
  .description('Cifra localmente y guarda una credencial (zero-knowledge)')
  .option('--env <env>', 'Entorno (dev/prod/staging)', 'dev')
  .action(async (key, value, options) => {
    try {
      const api = apiOrExit();
      const app = await api.getApp();

      console.log(`🔐 Cifrando credencial "${key}" localmente (zero-knowledge)...`);

      // The exact recipient set the server will verify against.
      const discovery = await api.getDiscovery(app.id);
      const recipients = discovery.recipients;
      if (!recipients || recipients.length === 0) {
        fail(
          'El recipient set de la app está vacío.\n' +
            '   Ejecuta `app-init` (controller + recovery) y/o attesta un dispositivo primero.',
        );
      }

      const envelope = encryptSecret(recipients, value);
      const saved = await api.postCredential(app.id, key, options.env, envelope);

      console.log(`✅ Credencial "${saved.key || key}" cifrada para ${recipients.length} destinatario(s) y guardada.`);
      console.log('   El servidor almacenó solo texto cifrado — ni Koove puede leerla. 🔒');
    } catch (error) {
      if (error.response?.status === 409) {
        const d = error.response.data;
        fail(
          'El servidor rechazó el envelope: destinatarios inconsistentes.\n' +
            `   faltan: ${JSON.stringify(d.missing)} — sobran: ${JSON.stringify(d.extra)}\n` +
            '   (¿cambió el recipient set a mitad? re-ejecuta el comando)',
        );
      }
      fail(httpError(error));
    }
  });

program
  .command('list')
  .description('Lista todas las credenciales de la app (solo metadatos)')
  .option('--env <env>', 'Filtrar por entorno')
  .action(async (options) => {
    try {
      const api = apiOrExit();
      const app = await api.getApp();
      let credentials = await api.getCredentials(app.id);
      if (options.env) credentials = credentials.filter((c) => c.env === options.env);
      if (credentials.length === 0) {
        console.log('No hay credenciales guardadas.');
        return;
      }
      console.table(
        credentials.map((c) => ({
          Key: c.key,
          Environment: c.env,
          Version: c.version,
          Recipients: c.envelope?.wraps ? Object.keys(c.envelope.wraps).length : '?',
          Created: new Date(c.createdAt).toLocaleString(),
        })),
      );
    } catch (error) {
      fail(httpError(error));
    }
  });

// ----- Device lifecycle ----- //

program
  .command('devices')
  .description('Lista los dispositivos de la app y su estado de re-wrap')
  .action(async () => {
    try {
      const api = apiOrExit();
      const app = await api.getApp();
      const discovery = await api.getDiscovery(app.id);
      if (discovery.devices.length === 0) {
        console.log('No hay dispositivos registrados.');
        return;
      }
      console.table(
        discovery.devices.map((d) => ({
          Id: d.id,
          Platform: d.platform,
          Status: d.status,
          Rewrap: d.rewrapStatus,
          Key: d.publicKey.slice(0, 12) + '…',
          Attested: new Date(d.attestedAt).toLocaleString(),
        })),
      );
      console.log(`Controller: ${discovery.controllerPublicKey ?? '(sin registrar)'}`);
      console.log(`Recovery:   ${discovery.recoveryPublicKey ?? '(sin registrar / opt-out)'}`);
    } catch (error) {
      fail(httpError(error));
    }
  });

program
  .command('device-approve')
  .description('Procesa los dispositivos pendientes: re-envuelve los secretos existentes para ellos')
  .action(async () => {
    try {
      const api = apiOrExit();
      const app = await api.getApp();
      const identity = await loadController(app.id);
      await runEngine(api, app.id, identity, 'controller');
    } catch (error) {
      fail(httpError(error));
    }
  });

program
  .command('device-revoke <deviceId>')
  .description('Revoca un dispositivo y ejecuta el kill criptográfico (lo saca de todos los envelopes)')
  .action(async (deviceId) => {
    try {
      const api = apiOrExit();
      const app = await api.getApp();
      const identity = await loadController(app.id);

      const revoked = await api.revokeDevice(app.id, deviceId);
      console.log(`🚫 Dispositivo ${revoked.id} revocado (SOFT). Ejecutando kill criptográfico...`);

      await runEngine(api, app.id, identity, 'controller');

      console.log(
        '✅ Kill HARD completo: el dispositivo ya no es destinatario de ningún envelope.\n' +
          '   ⚠️ Límite honesto: un plaintext que ese dispositivo ya descargó y cacheó no se\n' +
          '   des-entrega. Para un kill total, rota también el VALOR del secreto.',
      );
    } catch (error) {
      fail(httpError(error));
    }
  });

program
  .command('rewrap')
  .description('Fuerza la convergencia: todos los envelopes = recipient set actual (idempotente)')
  .action(async () => {
    try {
      const api = apiOrExit();
      const app = await api.getApp();
      const identity = await loadController(app.id);
      await runEngine(api, app.id, identity, 'controller');
    } catch (error) {
      fail(httpError(error));
    }
  });

// ----- Recovery (break-glass) ----- //

program
  .command('recover-show <key>')
  .description('Break-glass: descifra un secreto localmente con el código de recuperación')
  .option('--env <env>', 'Entorno', 'dev')
  .action(async (key, options) => {
    try {
      const api = apiOrExit();
      const app = await api.getApp();
      const mnemonic = await askHidden('Código de recuperación (24 palabras): ');
      const recovery = deriveRecoveryIdentity(mnemonic);

      const credentials = await api.getCredentials(app.id);
      const cred = credentials.find((c) => c.key === key && c.env === options.env);
      if (!cred) fail(`No existe la credencial "${key}" (${options.env}).`);

      const value = decryptSecret(recovery, cred.envelope);
      console.log(value);
      console.error('⚠️  Descifrado con el recovery code. Si no fuiste tú, rota el código y los valores.');
    } catch (error) {
      fail(httpError(error));
    }
  });

program
  .command('recover-rewrap')
  .description('Break-glass: re-envuelve con el código de recuperación (p.ej. tras registrar un dispositivo nuevo)')
  .action(async () => {
    try {
      const api = apiOrExit();
      const app = await api.getApp();
      const mnemonic = await askHidden('Código de recuperación (24 palabras): ');
      const recovery = deriveRecoveryIdentity(mnemonic);
      // The server audits this path distinctly ('recovery-rewrap') — a
      // compromised code is caught by its use, not hidden.
      await runEngine(api, app.id, recovery, 'recovery');
      console.log('ℹ️  Recomendado (no forzado): rota el recovery code (`recovery-rotate`).');
    } catch (error) {
      fail(httpError(error));
    }
  });

// ----- Rotation ----- //

program
  .command('controller-rotate')
  .description('Rota la identidad controller (un comando, sin downtime, resumable)')
  .option('--via-recovery', 'autoriza con el código de recuperación (controller perdido)')
  .action(async (options) => {
    try {
      const api = apiOrExit();
      const app = await api.getApp();
      const discovery = await api.getDiscovery(app.id);
      const livePath = keyfile.controllerKeyPath(app.id);
      const stagedPath = keyfile.controllerKeyPath(app.id, '.new');

      // Resume: a staged key already registered server-side means a previous
      // rotate was interrupted mid-re-wrap. Finish it instead of starting over.
      const staged = keyfile.peekPublicKey(stagedPath);
      const resuming = staged && discovery.controllerPublicKey === staged;

      // Authorizer: any identity that is still a recipient of the envelopes —
      // the OLD controller normally, or recovery if it was lost.
      let authorizer;
      let authorizedBy = 'controller';
      if (options.viaRecovery) {
        const mnemonic = await askHidden('Código de recuperación (24 palabras): ');
        authorizer = deriveRecoveryIdentity(mnemonic);
        authorizedBy = 'recovery';
      } else {
        authorizer = await loadController(app.id);
      }

      if (!resuming) {
        const next = generateIdentityKeyPair();
        const passphrase = await askPassphrase('Passphrase del NUEVO controller', { confirm: true });
        keyfile.saveIdentity(stagedPath, next, passphrase, { overwrite: true });
        await api.patchRecipients(app.id, { controllerPublicKey: next.publicKey });
        console.log('🔁 Nueva clave registrada. Re-envolviendo (add-before-remove por envelope)...');
      } else {
        console.log('♻️  Retomando una rotación interrumpida...');
      }

      await runEngine(api, app.id, authorizer, authorizedBy);

      // Converged: promote the staged keyfile; archive the old one (it opens
      // nothing anymore, but keep it out of prudence rather than deleting).
      if (fs.existsSync(livePath)) {
        fs.renameSync(livePath, keyfile.controllerKeyPath(app.id, `.old-${Date.now()}`));
      }
      fs.renameSync(stagedPath, livePath);
      console.log('✅ Rotación de controller completa. Keyfile nuevo activo.');
      console.log(
        '   ⚠️ Si rotaste por COMPROMISO: esto solo protege el futuro. Rota también los\n' +
          '   VALORES de los secretos — la clave vieja pudo leer lo ya entregado.',
      );
    } catch (error) {
      fail(httpError(error));
    }
  });

program
  .command('recovery-rotate')
  .description('Rota el código de recuperación (controller-driven; muestra el código nuevo una vez)')
  .action(async () => {
    try {
      const api = apiOrExit();
      const app = await api.getApp();
      const identity = await loadController(app.id);

      const mnemonic = generateRecoveryCode();
      const newPub = deriveRecoveryIdentity(mnemonic).publicKey;

      // Show BEFORE the re-wrap: if the run is interrupted, re-running issues
      // a fresh code (the old one keeps working until convergence removes it).
      printMnemonicOnce(mnemonic, 'NUEVO CÓDIGO DE RECUPERACIÓN (24 palabras BIP39)');
      await confirmSaved();

      await api.patchRecipients(app.id, { recoveryPublicKey: newPub });
      await runEngine(api, app.id, identity, 'controller');

      console.log('✅ Rotación de recovery completa. El código anterior ya no abre nada.');
      console.log(
        '   ⚠️ Si rotaste por COMPROMISO: rota también los VALORES — el código viejo pudo\n' +
          '   leer lo ya entregado.',
      );
    } catch (error) {
      fail(httpError(error));
    }
  });

program.parse(process.argv);
