#!/usr/bin/env node
const { program } = require('commander');
const axios = require('axios');
const { encryptSecret } = require('@koove/crypto');
const fs = require('fs');
const path = require('path');
const os = require('os');

// Configuración
const CONFIG_DIR = path.join(os.homedir(), '.koove-secrets');
const CONFIG_FILE = path.join(CONFIG_DIR, 'config.json');

// Asegurar que el directorio de configuración existe
if (!fs.existsSync(CONFIG_DIR)) {
  fs.mkdirSync(CONFIG_DIR, { recursive: true });
}

// Cargar configuración
function loadConfig() {
  if (fs.existsSync(CONFIG_FILE)) {
    return JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
  }
  return {};
}

// Guardar configuración
function saveConfig(config) {
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2));
}

// Recopila las claves públicas (X25519, base64) de los consumidores autorizados
// de una app: dispositivos/servicios que han registrado su identidad.
function collectRecipients(app) {
  const keys = new Set();
  if (app && app.publicKey) keys.add(app.publicKey);
  if (app && Array.isArray(app.consumers)) {
    for (const c of app.consumers) {
      if (c && c.publicKey) keys.add(c.publicKey);
    }
  }
  return [...keys];
}

// Configuración básica
program
  .name('koove-secrets')
  .description('CLI para gestionar credenciales seguras con Koove VPN')
  .version('1.0.0');

// ----- Comandos principales ----- //

// Test de conexión
program
  .command('test')
  .description('Verifica que la CLI funcione')
  .action(() => {
    console.log('✅ ¡CLI operativa!');
  });

// Configuración
program
  .command('config')
  .description('Configura la CLI')
  .option('--api-url <url>', 'URL de la API')
  .option('--app-token <token>', 'Token de la aplicación')
  .action((options) => {
    const config = loadConfig();

    if (options.apiUrl) {
      config.apiUrl = options.apiUrl;
    }
    if (options.appToken) {
      config.appToken = options.appToken;
    }

    saveConfig(config);
    console.log('✅ Configuración guardada en:', CONFIG_FILE);
    console.log('API URL:', config.apiUrl || '(no configurada)');
    console.log('App Token:', config.appToken ? '***' + config.appToken.slice(-4) : '(no configurado)');
  });

// Gestión de credenciales
program
  .command('set <key> <value>')
  .description('Guarda una credencial encriptada')
  .option('--env <env>', 'Entorno (dev/prod/staging)', 'dev')
  .action(async (key, value, options) => {
    try {
      const config = loadConfig();

      if (!config.apiUrl || !config.appToken) {
        console.error('❌ Error: Configuración incompleta.');
        console.error('Ejecuta: koove-secrets config --api-url=<url> --app-token=<token>');
        process.exit(1);
      }

      console.log(`🔐 Cifrando credencial "${key}" localmente (zero-knowledge)...`);

      // 1. Obtener la app y los consumidores autorizados (sus claves públicas)
      const appsResponse = await axios.get(`${config.apiUrl}/api/apps`, {
        headers: {
          'Authorization': `Bearer ${config.appToken}`
        }
      });

      const apps = appsResponse.data;
      if (!apps || apps.length === 0) {
        console.error('❌ Error: No se encontró ninguna app asociada al token.');
        process.exit(1);
      }

      const app = apps[0];
      const appId = app.id;

      const recipients = collectRecipients(app);
      if (recipients.length === 0) {
        console.error('❌ Error: ningún consumidor ha registrado su identidad todavía.');
        console.error('   Inicia la app (SDK) o el servicio backend una vez para que registre');
        console.error('   su clave pública; sin un destinatario no se puede cifrar el secreto.');
        process.exit(1);
      }

      // 2. Cifrado de sobre LOCAL. El servidor nunca verá el valor en claro.
      const envelope = encryptSecret(recipients, value);

      // 3. Subir SOLO el envelope cifrado (sin el valor en claro).
      const response = await axios.post(
        `${config.apiUrl}/api/credentials`,
        {
          appId,
          key,
          env: options.env,
          envelope
        },
        {
          headers: {
            'Authorization': `Bearer ${config.appToken}`,
            'Content-Type': 'application/json'
          }
        }
      );

      console.log(
        `✅ Credencial "${response.data.key || key}" cifrada para ${recipients.length} consumidor(es) y guardada.`
      );
      console.log('   El servidor almacenó solo texto cifrado — ni Koove puede leerla. 🔒');
    } catch (error) {
      console.error('❌ Error:', error.response?.data || error.message);
      process.exit(1);
    }
  });

// Listar credenciales
program
  .command('list')
  .description('Lista todas las credenciales de la app')
  .option('--env <env>', 'Filtrar por entorno')
  .action(async (options) => {
    try {
      const config = loadConfig();

      if (!config.apiUrl || !config.appToken) {
        console.error('❌ Error: Configuración incompleta.');
        console.error('Ejecuta: koove-secrets config --api-url=<url> --app-token=<token>');
        process.exit(1);
      }

      console.log('📋 Listando credenciales...');

      const response = await axios.get(`${config.apiUrl}/api/credentials`, {
        headers: {
          'Authorization': `Bearer ${config.appToken}`
        }
      });

      let credentials = response.data;

      if (options.env) {
        credentials = credentials.filter(c => c.env === options.env);
      }

      if (credentials.length === 0) {
        console.log('No hay credenciales guardadas.');
        return;
      }

      console.table(credentials.map(c => ({
        Key: c.key,
        Environment: c.env,
        Created: new Date(c.createdAt).toLocaleString()
      })));
    } catch (error) {
      console.error('❌ Error:', error.response?.data || error.message);
      process.exit(1);
    }
  });

// ----- Ejecutar CLI ----- //
program.parse(process.argv);