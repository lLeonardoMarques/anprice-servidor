// =============================================
// ANPRICE - INICIALIZAÇÃO DO SERVIDOR
// Lê as variáveis de ambiente, conecta ao MongoDB e sobe o Express.
// A lógica fica em app.js (testável sem rede).
// =============================================

import { MongoClient } from 'mongodb';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createApp, criarIndices } from './app.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const required = [
  'MELI_CLIENT_ID',
  'MELI_CLIENT_SECRET',
  'MELI_REDIRECT_URI',
  'MONGO_URI',
  'TOKEN_ENCRYPTION_KEY',
  'ADMIN_PASSWORD'
];

const missing = required.filter(k => !process.env[k]);
if (missing.length) {
  throw new Error('Variaveis ausentes: ' + missing.join(', '));
}

if (!/^[a-f0-9]{64}$/i.test(process.env.TOKEN_ENCRYPTION_KEY)) {
  throw new Error('TOKEN_ENCRYPTION_KEY deve conter 64 caracteres hexadecimais');
}

if (process.env.ADMIN_PASSWORD.length < 16) {
  throw new Error('ADMIN_PASSWORD deve ter ao menos 16 caracteres');
}

// A origem pública do app é a do próprio Render. Por padrão ela é
// derivada de MELI_REDIRECT_URI, que já aponta para este serviço.
const appOrigin = new URL(process.env.PUBLIC_URL || process.env.MELI_REDIRECT_URI).origin;

const extraOrigins = String(process.env.EXTRA_ALLOWED_ORIGINS || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean)
  .map(s => new URL(s).origin);

const mongo = new MongoClient(process.env.MONGO_URI);
await mongo.connect();
const db = mongo.db('anprice');
await criarIndices(db);

const app = createApp({
  db,
  config: {
    clientId: process.env.MELI_CLIENT_ID,
    clientSecret: process.env.MELI_CLIENT_SECRET,
    redirectUri: process.env.MELI_REDIRECT_URI,
    encryptionKey: Buffer.from(process.env.TOKEN_ENCRYPTION_KEY, 'hex'),
    adminPassword: process.env.ADMIN_PASSWORD,
    appOrigin,
    extraOrigins,
    webDist: process.env.WEB_DIST || path.join(__dirname, 'web', 'dist'),
    diagnosticoAtivo: process.env.DIAGNOSTICO_ATIVO !== 'false'
  }
});

const PORT = Number(process.env.PORT || 3000);

app.listen(PORT, '0.0.0.0', () => {
  console.log('AnPrice API iniciada');
  console.log('Origem do app:', appOrigin);
});
