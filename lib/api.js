'use strict';
/**
 * Thin client for the Koove control plane. Every call authenticates with the
 * app token; the server only ever sees public keys and ciphertext envelopes.
 */
const axios = require('axios');

function createApi(config) {
  if (!config.apiUrl || !config.appToken) {
    const err = new Error(
      'Configuración incompleta. Ejecuta: koove-secrets config --api-url=<url> --app-token=<token>',
    );
    err.code = 'ECONFIG';
    throw err;
  }
  const http = axios.create({
    baseURL: config.apiUrl,
    headers: { Authorization: `Bearer ${config.appToken}` },
  });

  let cachedApp = null;

  return {
    /** The app bound to the configured token. */
    async getApp() {
      if (cachedApp) return cachedApp;
      const { data } = await http.get('/api/apps');
      if (!Array.isArray(data) || data.length === 0) {
        throw new Error('No se encontró ninguna app asociada al token.');
      }
      cachedApp = data[0];
      return cachedApp;
    },

    /** Composed discovery: recipients (exact wrap set) + all devices + always-keys. */
    async getDiscovery(appId) {
      const { data } = await http.get(`/api/apps/${appId}/devices`);
      return data;
    },

    /** All credentials of the app: { key, env, envelope, version, ... }. */
    async getCredentials(appId) {
      const { data } = await http.get('/api/credentials', { params: { appId } });
      return data;
    },

    /** Write one secret envelope (the normal `set` path). */
    async postCredential(appId, key, env, envelope) {
      const { data } = await http.post('/api/credentials', { appId, key, env, envelope });
      return data;
    },

    /** Batch re-wrap upload. Returns { results, clearedDevices, recipients }. */
    async putRewrap(appId, items, authorizedBy) {
      const { data } = await http.put(`/api/apps/${appId}/credentials/rewrap`, {
        items,
        authorizedBy,
      });
      return data;
    },

    /** Register / rotate the always-recipient public keys. */
    async patchRecipients(appId, body) {
      const { data } = await http.patch(`/api/apps/${appId}/recipients`, body);
      return data;
    },

    /** SOFT-revoke a device (the engine then makes it HARD). */
    async revokeDevice(appId, deviceId) {
      const { data } = await http.post(`/api/apps/${appId}/devices/${deviceId}/revoke`);
      return data;
    },
  };
}

module.exports = { createApi };
