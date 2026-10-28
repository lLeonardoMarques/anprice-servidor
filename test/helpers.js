// Utilitários de teste: banco em memória compatível com o subconjunto
// do driver MongoDB usado pelo AnPrice e um Mercado Livre simulado.

import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createApp } from '../app.js';

function combina(doc, filtro) {
  return Object.entries(filtro).every(([campo, cond]) => {
    const v = doc[campo];
    if (cond && typeof cond === 'object' && !(cond instanceof Date) && '$gt' in cond) {
      return v != null && v > cond.$gt;
    }
    return v === cond;
  });
}

class Colecao {
  constructor() {
    this.docs = [];
  }
  async findOne(f) {
    return this.docs.find(d => combina(d, f)) || null;
  }
  async insertOne(doc) {
    const d = { _id: doc._id ?? crypto.randomUUID(), ...doc };
    if (this.docs.some(x => x._id === d._id)) throw Object.assign(new Error('dup'), { name: 'MongoServerError' });
    this.docs.push(d);
    return { insertedId: d._id };
  }
  async deleteOne(f) {
    const i = this.docs.findIndex(d => combina(d, f));
    if (i >= 0) this.docs.splice(i, 1);
    return { deletedCount: i >= 0 ? 1 : 0 };
  }
  async deleteMany(f) {
    const antes = this.docs.length;
    this.docs = this.docs.filter(d => !combina(d, f));
    return { deletedCount: antes - this.docs.length };
  }
  async findOneAndDelete(f) {
    const d = await this.findOne(f);
    if (d) await this.deleteOne({ _id: d._id });
    return d;
  }
  async replaceOne(f, doc, { upsert } = {}) {
    const i = this.docs.findIndex(d => combina(d, f));
    if (i >= 0) this.docs[i] = doc;
    else if (upsert) this.docs.push(doc);
  }
  async updateOne(f, { $set }) {
    const d = await this.findOne(f);
    if (d) Object.assign(d, $set);
  }
  async countDocuments(f) {
    return this.docs.filter(d => combina(d, f)).length;
  }
}

export function fakeDb() {
  const cols = new Map();
  return {
    collection(nome) {
      if (!cols.has(nome)) cols.set(nome, new Colecao());
      return cols.get(nome);
    }
  };
}

const json = (status, body) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

export const POLICY_403 = {
  blocked_by: 'PolicyAgent',
  message: 'At least one policy returned UNAUTHORIZED.',
  code: 'PA_UNAUTHORIZED_RESULT_FROM_POLICIES',
  status: 403
};

// Mercado Livre simulado. `rotas` mapeia prefixo de caminho → função
// (url, init) => Response. Registra as chamadas em `chamadas`.
export function fakeMeli(rotas) {
  const chamadas = [];
  const fetchImpl = async (url, init = {}) => {
    const u = new URL(url);
    chamadas.push({ caminho: u.pathname + u.search, init });
    const chave = Object.keys(rotas)
      .sort((a, b) => b.length - a.length)
      .find(k => (u.pathname + u.search).startsWith(k));
    if (!chave) return json(404, { message: 'not_found' });
    return rotas[chave](u, init);
  };
  return { fetchImpl, chamadas, json };
}

export const SENHA = 'senha-de-teste-com-mais-de-16';
export const ORIGEM = 'https://anprice.test';

export async function iniciar({ rotas = {}, comFrontend = false, config = {} } = {}) {
  const db = fakeDb();
  const meli = fakeMeli(rotas);
  let webDist = null;
  if (comFrontend) {
    webDist = fs.mkdtempSync(path.join(os.tmpdir(), 'anprice-web-'));
    fs.mkdirSync(path.join(webDist, 'assets'));
    fs.writeFileSync(path.join(webDist, 'index.html'), '<!doctype html><div id="root"></div>');
    fs.writeFileSync(path.join(webDist, 'assets', 'app.js'), 'console.log(1)');
  }
  const logs = [];
  const log = {
    log: (...a) => logs.push(a),
    warn: (...a) => logs.push(a),
    error: (...a) => logs.push(a)
  };
  const app = createApp({
    db,
    fetchImpl: meli.fetchImpl,
    log,
    config: {
      clientId: 'client-id-teste',
      clientSecret: 'client-secret-teste',
      redirectUri: ORIGEM + '/auth/mercadolivre/callback',
      encryptionKey: crypto.randomBytes(32),
      adminPassword: SENHA,
      appOrigin: ORIGEM,
      webDist,
      meliApiBase: 'https://ml.test',
      meliAuthUrl: 'https://auth.ml.test/authorization',
      ...config
    }
  });
  const server = await new Promise(r => {
    const s = app.listen(0, '127.0.0.1', () => r(s));
  });
  const base = `http://127.0.0.1:${server.address().port}`;

  let cookie = null;
  async function req(caminho, { method = 'GET', body, origin = ORIGEM, semCookie = false, headers = {} } = {}) {
    const h = { ...headers };
    if (origin && method !== 'GET') h.Origin = origin;
    if (body !== undefined) h['Content-Type'] = 'application/json';
    if (cookie && !semCookie) h.Cookie = cookie;
    const r = await fetch(base + caminho, {
      method,
      headers: h,
      body: body === undefined ? undefined : JSON.stringify(body),
      redirect: 'manual'
    });
    const sc = r.headers.get('set-cookie');
    if (sc) {
      const valor = sc.split(';')[0];
      cookie = valor.endsWith('=') ? null : valor;
    }
    const tipo = r.headers.get('content-type') || '';
    const dados = tipo.includes('json') ? await r.json() : await r.text();
    return { status: r.status, headers: r.headers, dados, setCookie: sc };
  }

  async function login() {
    const r = await req('/api/login', { method: 'POST', body: { password: SENHA } });
    if (r.status !== 200) throw new Error('login falhou: ' + r.status);
    return r;
  }

  // Conecta o Mercado Livre pelo fluxo OAuth real (iniciar → callback).
  async function conectar() {
    const r = await req('/api/auth/iniciar', { method: 'POST' });
    const state = new URL(r.dados.url).searchParams.get('state');
    const cb = await req(`/auth/mercadolivre/callback?code=CODE&state=${encodeURIComponent(state)}`, { semCookie: true });
    if (cb.headers.get('location') !== '/?ml=conectado') throw new Error('conexão OAuth falhou: ' + cb.status);
    return cb;
  }

  return { db, meli, req, login, conectar, logs, base, close: () => { server.closeAllConnections(); server.close(); } };
}

export const tokenOk = () =>
  json(200, { access_token: 'AT-' + crypto.randomUUID(), refresh_token: 'RT-1', expires_in: 21600, user_id: 1 });
export { json };
