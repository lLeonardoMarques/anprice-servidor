// =============================================
// ANPRICE - APLICAÇÃO (API + FRONTEND NA MESMA ORIGEM)
// Login, MongoDB, OAuth 2.0 com PKCE e Mercado Livre
// =============================================

import express from 'express';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {
  MeliError,
  HTTP_POR_CODIGO,
  createMeliClient,
  buscarProdutos,
  diagnosticarEndpoints,
  extrairReferencia
} from './meli.js';

const SESSAO_MS = 8 * 60 * 60 * 1000;
const STATE_MS = 10 * 60 * 1000;
const LOGIN_JANELA_MS = 15 * 60 * 1000;
const LOGIN_MAX_POR_IP = 10;
const LOGIN_MAX_GLOBAL = 30;
const CACHE_BUSCA_MS = 3 * 60 * 1000;

const COOKIE = 'anprice_session';

// Mensagens exibidas ao usuário para cada código de erro.
const MENSAGENS = {
  SESSAO_AUSENTE: 'Faça login de administrador.',
  SESSAO_EXPIRADA: 'Sessão expirada. Faça login novamente.',
  ORIGEM_NAO_PERMITIDA: 'Requisição recusada: origem não permitida.',
  SENHA_INVALIDA: 'Senha inválida.',
  LOGIN_LIMITE: 'Muitas tentativas de login. Aguarde alguns minutos.',
  BUSCA_INVALIDA: 'Informe uma busca entre 2 e 100 caracteres.',
  BANCO_INDISPONIVEL: 'Banco de dados indisponível no momento.',
  ERRO_INTERNO: 'Erro interno do servidor.',
  DIAGNOSTICO_DESATIVADO: 'Diagnóstico desativado neste servidor.',
  REFERENCIA_INVALIDA:
    'Link ou código não reconhecido. Use o link de um anúncio do Mercado Livre ou um código como MLB1234567890.',
  ML_NAO_CONECTADO: 'Conecte a conta do Mercado Livre primeiro.',
  ML_REAUTORIZAR: 'A autorização do Mercado Livre expirou ou foi revogada. Conecte a conta novamente.',
  ML_TOKEN_INVALIDO: 'O Mercado Livre recusou o token de acesso. Conecte a conta novamente.',
  ML_BLOQUEADO_POLITICA:
    'O Mercado Livre bloqueou esta consulta por política de acesso da aplicação (PolicyAgent). Não é falha do servidor nem do token.',
  ML_SEM_PERMISSAO: 'A aplicação não tem permissão para este recurso do Mercado Livre.',
  ML_NAO_ENCONTRADO: 'Recurso não encontrado no Mercado Livre.',
  ML_LIMITE: 'Limite de requisições do Mercado Livre atingido. Aguarde alguns instantes.',
  ML_TEMPO_ESGOTADO: 'O Mercado Livre não respondeu a tempo. Tente novamente.',
  ML_INDISPONIVEL: 'A API do Mercado Livre está indisponível no momento.',
  ML_OAUTH_FALHOU: 'Falha ao renovar a autorização com o Mercado Livre.',
  ML_RESPOSTA_INVALIDA: 'Resposta inesperada da API do Mercado Livre.'
};

function erro(res, status, codigo, extra = {}) {
  return res.status(status).json({ codigo, erro: MENSAGENS[codigo] || codigo, ...extra });
}

function responderMeliError(res, err) {
  const status = HTTP_POR_CODIGO[err.codigo] || 502;
  const extra = {};
  if (err.statusMercadoLivre != null) extra.statusMercadoLivre = err.statusMercadoLivre;
  if (err.politica) extra.politica = err.politica;
  if (err.endpoint) extra.endpoint = err.endpoint;
  if (err.tentativas) extra.tentativas = err.tentativas;
  return erro(res, status, err.codigo, extra);
}

export function createApp({ db, config, fetchImpl = fetch, log = console }) {
  const {
    clientId,
    clientSecret,
    redirectUri,
    encryptionKey,
    adminPassword,
    appOrigin,
    extraOrigins = [],
    webDist,
    meliApiBase = 'https://api.mercadolibre.com',
    meliAuthUrl = 'https://auth.mercadolivre.com.br/authorization',
    diagnosticoAtivo = true
  } = config;

  const allowedOrigins = new Set([appOrigin, ...extraOrigins]);

  const tokens = db.collection('tokens');
  const states = db.collection('oauth_states');
  const sessions = db.collection('sessions');
  const loginAttempts = db.collection('login_attempts');

  // ---------- Criptografia ----------

  const hash = s => crypto.createHash('sha256').update(s).digest('hex');
  const random = () => crypto.randomBytes(32).toString('base64url');

  function seal(obj) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey, iv);
    const data = Buffer.concat([cipher.update(JSON.stringify(obj), 'utf8'), cipher.final()]);
    return [iv, cipher.getAuthTag(), data].map(b => b.toString('base64url')).join('.');
  }

  function unseal(value) {
    const [iv, tag, data] = String(value).split('.').map(x => Buffer.from(x, 'base64url'));
    const decipher = crypto.createDecipheriv('aes-256-gcm', encryptionKey, iv);
    decipher.setAuthTag(tag);
    return JSON.parse(Buffer.concat([decipher.update(data), decipher.final()]).toString());
  }

  function sessionCookie(req) {
    const c = (req.headers.cookie || '')
      .split(';')
      .map(x => x.trim())
      .find(x => x.startsWith(COOKIE + '='));
    return c ? c.slice(COOKIE.length + 1) : null;
  }

  // Frontend e API na mesma origem: SameSite=Lax basta e o cookie
  // deixa de ser "de terceiros". Lax também barra POSTs entre sites.
  const cookieFlags = `HttpOnly; Secure; SameSite=Lax; Path=/`;

  const ipHash = req => hash('ip:' + (req.ip || 'desconhecido')).slice(0, 32);

  // ---------- App ----------

  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', 1);

  app.use((req, res, next) => {
    res.set('X-Content-Type-Options', 'nosniff');
    res.set('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.set('X-Frame-Options', 'DENY');
    res.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    if (req.secure) {
      res.set('Strict-Transport-Security', 'max-age=31536000');
    }
    if (req.path.startsWith('/api/') || req.path.startsWith('/auth/')) {
      res.set('Cache-Control', 'no-store');
    }
    next();
  });

  app.use(express.json({ limit: '4kb' }));

  // Proteção CSRF para rotas que alteram estado.
  // Navegadores sempre enviam Origin em POST via fetch.
  function mesmaOrigem(req, res, next) {
    const origin = req.headers.origin;
    if (origin ? allowedOrigins.has(origin) : req.headers['sec-fetch-site'] === 'same-origin') {
      return next();
    }
    return erro(res, 403, 'ORIGEM_NAO_PERMITIDA');
  }

  async function auth(req, res, next) {
    try {
      const s = sessionCookie(req);
      if (!s) return erro(res, 401, 'SESSAO_AUSENTE');
      const sessao = await sessions.findOne({ _id: hash(s), expires: { $gt: new Date() } });
      if (!sessao) return erro(res, 401, 'SESSAO_EXPIRADA');
      req.sessionHash = hash(s);
      next();
    } catch {
      erro(res, 503, 'BANCO_INDISPONIVEL');
    }
  }

  // ---------- Saúde ----------

  app.get('/health', (req, res) => res.json({ status: 'ok' }));

  // ---------- Login (limite por IP e global, persistido no MongoDB) ----------

  app.post('/api/login', mesmaOrigem, async (req, res, next) => {
    try {
      const agora = new Date();
      const desde = new Date(agora.getTime() - LOGIN_JANELA_MS);
      const ip = ipHash(req);

      const [porIp, global] = await Promise.all([
        loginAttempts.countDocuments({ ip, at: { $gt: desde } }),
        loginAttempts.countDocuments({ at: { $gt: desde } })
      ]);

      if (porIp >= LOGIN_MAX_POR_IP || global >= LOGIN_MAX_GLOBAL) {
        return erro(res, 429, 'LOGIN_LIMITE');
      }

      const supplied = Buffer.from(String(req.body?.password || ''));
      const expected = Buffer.from(adminPassword);
      const ok =
        supplied.length === expected.length && crypto.timingSafeEqual(supplied, expected);

      if (!ok) {
        await loginAttempts.insertOne({
          ip,
          at: agora,
          expires: new Date(agora.getTime() + LOGIN_JANELA_MS)
        });
        log.warn('[ANPRICE][LOGIN]', { resultado: 'falha', tentativasIp: porIp + 1 });
        return erro(res, 401, 'SENHA_INVALIDA');
      }

      await loginAttempts.deleteMany({ ip });

      const s = random();
      await sessions.insertOne({ _id: hash(s), expires: new Date(Date.now() + SESSAO_MS) });

      res.set('Set-Cookie', `${COOKIE}=${s}; ${cookieFlags}; Max-Age=${SESSAO_MS / 1000}`);
      res.json({ ok: true });
    } catch (err) {
      next(err);
    }
  });

  app.post('/api/logout', mesmaOrigem, async (req, res, next) => {
    try {
      const s = sessionCookie(req);
      if (s) await sessions.deleteOne({ _id: hash(s) });
      res.set('Set-Cookie', `${COOKIE}=; ${cookieFlags}; Max-Age=0`);
      res.json({ ok: true });
    } catch (err) {
      next(err);
    }
  });

  // ---------- Token do Mercado Livre ----------

  async function oauth(params) {
    let resposta;
    try {
      resposta = await fetchImpl(meliApiBase + '/oauth/token', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Accept: 'application/json'
        },
        body: new URLSearchParams({ ...params, client_id: clientId, client_secret: clientSecret }),
        signal: AbortSignal.timeout(15000)
      });
    } catch {
      throw new MeliError('ML_OAUTH_FALHOU', { endpoint: '/oauth/token' });
    }

    if (!resposta.ok) {
      let body = {};
      try {
        body = await resposta.json();
      } catch {
        body = {};
      }
      const oauthErro = typeof body?.error === 'string' ? body.error.slice(0, 60) : null;
      log.error('[ANPRICE][OAUTH]', { status: resposta.status, erro: oauthErro });
      // invalid_grant: refresh token usado, expirado ou revogado → reconectar.
      const reautorizar = resposta.status === 400 && oauthErro === 'invalid_grant';
      throw new MeliError(reautorizar ? 'ML_REAUTORIZAR' : 'ML_OAUTH_FALHOU', {
        statusMercadoLivre: resposta.status,
        politica: oauthErro,
        endpoint: '/oauth/token'
      });
    }

    const t = await resposta.json();
    if (!t.access_token || !t.refresh_token || !t.expires_in) {
      throw new MeliError('ML_OAUTH_FALHOU', { endpoint: '/oauth/token' });
    }
    return {
      access_token: t.access_token,
      refresh_token: t.refresh_token,
      user_id: t.user_id ?? null,
      scope: typeof t.scope === 'string' ? t.scope : null,
      expires_at: Date.now() + Number(t.expires_in) * 1000
    };
  }

  async function lerToken() {
    const row = await tokens.findOne({ _id: 'principal' });
    if (!row) throw new MeliError('ML_NAO_CONECTADO');
    try {
      return unseal(row.data);
    } catch {
      // Chave TOKEN_ENCRYPTION_KEY trocada ou dado corrompido.
      log.error('[ANPRICE][TOKEN]', { codigo: 'DECIFRAR_FALHOU' });
      throw new MeliError('ML_REAUTORIZAR');
    }
  }

  // Um único processo no Render: renovações simultâneas compartilham a mesma promessa.
  let refreshInProgress = null;

  async function getToken({ force = false } = {}) {
    const atual = await lerToken();
    if (!force && Date.now() < atual.expires_at - 60000) return atual.access_token;

    if (!refreshInProgress) {
      refreshInProgress = (async () => {
        const valor = await lerToken();
        if (!force && Date.now() < valor.expires_at - 60000) return valor.access_token;
        try {
          const novo = await oauth({
            grant_type: 'refresh_token',
            refresh_token: valor.refresh_token
          });
          await tokens.updateOne({ _id: 'principal' }, { $set: { data: seal(novo) } });
          return novo.access_token;
        } catch (err) {
          if (err instanceof MeliError && err.codigo === 'ML_REAUTORIZAR') {
            await tokens.deleteOne({ _id: 'principal' });
          }
          throw err;
        }
      })().finally(() => {
        refreshInProgress = null;
      });
    }
    return refreshInProgress;
  }

  const meli = createMeliClient({ fetchImpl, apiBase: meliApiBase, getToken });

  // ---------- Status e OAuth ----------

  app.get('/api/status', auth, async (req, res, next) => {
    try {
      const row = await tokens.findOne({ _id: 'principal' });
      res.json({ conectado: !!row, diagnosticoAtivo });
    } catch (err) {
      next(err);
    }
  });

  app.post('/api/auth/iniciar', mesmaOrigem, auth, async (req, res, next) => {
    try {
      const state = random();
      const verifier = random();
      const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');

      await states.insertOne({
        _id: hash(state),
        verifier: seal({ verifier }),
        sessionHash: req.sessionHash,
        expires: new Date(Date.now() + STATE_MS)
      });

      const url = new URL(meliAuthUrl);
      for (const [k, v] of Object.entries({
        response_type: 'code',
        client_id: clientId,
        redirect_uri: redirectUri,
        state,
        code_challenge: challenge,
        code_challenge_method: 'S256'
      })) {
        url.searchParams.set(k, v);
      }

      res.json({ url: url.toString() });
    } catch (err) {
      next(err);
    }
  });

  // O callback é validado pelo `state` (256 bits, uso único, 10 min) + PKCE.
  // Não depende do cookie: funciona mesmo em navegadores que isolam cookies.
  // O `state` só é criado por um administrador autenticado em /api/auth/iniciar.
  app.get('/auth/mercadolivre/callback', async (req, res) => {
    const voltar = (resultado, motivo) => {
      const destino = new URL('/', appOrigin);
      destino.searchParams.set('ml', resultado);
      if (motivo) destino.searchParams.set('motivo', motivo);
      res.redirect(303, destino.pathname + destino.search);
    };

    try {
      if (req.query.error) {
        return voltar('erro', 'AUTORIZACAO_NEGADA');
      }

      const state = String(req.query.state || '');
      const code = String(req.query.code || '');
      if (!state || !code) return voltar('erro', 'PARAMETROS_AUSENTES');

      const registro = await states.findOneAndDelete({
        _id: hash(state),
        expires: { $gt: new Date() }
      });
      if (!registro) return voltar('erro', 'STATE_INVALIDO');

      const { verifier } = unseal(registro.verifier);
      const t = await oauth({
        grant_type: 'authorization_code',
        code,
        redirect_uri: redirectUri,
        code_verifier: verifier
      });

      await tokens.replaceOne({ _id: 'principal' }, { _id: 'principal', data: seal(t) }, { upsert: true });
      cacheBusca.clear();
      log.log('[ANPRICE][OAUTH]', { resultado: 'conectado' });
      return voltar('conectado');
    } catch (err) {
      log.error('[ANPRICE][OAUTH_CALLBACK]', {
        codigo: err instanceof MeliError ? err.codigo : err?.name || 'Erro'
      });
      return voltar('erro', 'TROCA_FALHOU');
    }
  });

  // ---------- Busca ----------

  const cacheBusca = new Map();

  function lerCache(chave) {
    const e = cacheBusca.get(chave);
    if (!e) return null;
    if (Date.now() > e.expira) {
      cacheBusca.delete(chave);
      return null;
    }
    return e.valor;
  }

  function gravarCache(chave, valor) {
    if (cacheBusca.size >= 100) cacheBusca.delete(cacheBusca.keys().next().value);
    cacheBusca.set(chave, { valor, expira: Date.now() + CACHE_BUSCA_MS });
  }

  app.get('/api/buscar', auth, async (req, res, next) => {
    const q = String(req.query.q || '').trim();
    if (q.length < 2 || q.length > 100) return erro(res, 400, 'BUSCA_INVALIDA');

    const chave = q.toLowerCase();
    const emCache = lerCache(chave);
    if (emCache) return res.json({ ...emCache, cache: true });

    try {
      const r = await buscarProdutos(meli, q);
      const payload = {
        consulta: q,
        consultadoEm: new Date().toISOString(),
        fonte: r.fonte,
        resultados: r.resultados,
        totalInformado: r.totalInformado,
        tentativas: r.tentativas
      };
      gravarCache(chave, payload);
      res.json(payload);
    } catch (err) {
      if (err instanceof MeliError) {
        log.error('[ANPRICE][BUSCA]', {
          codigo: err.codigo,
          statusMercadoLivre: err.statusMercadoLivre,
          politica: err.politica,
          endpoint: err.endpoint,
          tentativas: err.tentativas
        });
        return responderMeliError(res, err);
      }
      next(err);
    }
  });

  // ---------- Diagnóstico (temporário; desligue com DIAGNOSTICO_ATIVO=false) ----------

  function diagnostico(req, res, next) {
    if (!diagnosticoAtivo) return erro(res, 404, 'DIAGNOSTICO_DESATIVADO');
    next();
  }

  app.get('/api/diagnostico/token', auth, diagnostico, async (req, res, next) => {
    try {
      const r = await meli.sondar('/users/me', '/users/me');
      res.json({ teste: 'users/me', statusMercadoLivre: r.status, autorizado: r.codigo === 'OK', codigo: r.codigo });
    } catch (err) {
      if (err instanceof MeliError) return responderMeliError(res, err);
      next(err);
    }
  });

  app.get('/api/diagnostico/endpoints', auth, diagnostico, async (req, res, next) => {
    const textoRef = String(req.query.ref || '').trim();
    const ref = textoRef ? extrairReferencia(textoRef) : null;
    if (textoRef && !ref) return erro(res, 400, 'REFERENCIA_INVALIDA');
    try {
      const resultados = await diagnosticarEndpoints(meli, { ref });
      log.log('[ANPRICE][DIAGNOSTICO]', resultados.map(r => `${r.endpoint}=${r.status ?? '-'}:${r.codigo}`).join(' '));
      res.json({ executadoEm: new Date().toISOString(), referencia: ref, resultados });
    } catch (err) {
      if (err instanceof MeliError) return responderMeliError(res, err);
      next(err);
    }
  });

  app.use('/api', (req, res) => res.status(404).json({ codigo: 'ROTA_INEXISTENTE', erro: 'Rota inexistente.' }));

  // ---------- Frontend estático (mesma origem) ----------

  const indexHtml = webDist ? path.join(webDist, 'index.html') : null;
  const temFrontend = Boolean(indexHtml && fs.existsSync(indexHtml));

  const CSP = [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src 'self' https://fonts.gstatic.com data:",
    "img-src 'self' data: https:",
    "connect-src 'self'",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "object-src 'none'"
  ].join('; ');

  if (temFrontend) {
    app.use(
      express.static(webDist, {
        index: false,
        setHeaders(res, arquivo) {
          if (arquivo.includes(`${path.sep}assets${path.sep}`)) {
            res.set('Cache-Control', 'public, max-age=31536000, immutable');
          }
        }
      })
    );
  }

  // Qualquer outra rota GET devolve o app (SPA).
  app.use((req, res, next) => {
    if (req.method !== 'GET' && req.method !== 'HEAD') return next();
    if (req.path.startsWith('/auth/')) return next();
    if (!temFrontend) {
      return res
        .status(503)
        .type('text/plain')
        .send('Frontend não compilado neste servidor. Rode "npm run build".');
    }
    res.set('Cache-Control', 'no-cache');
    res.set('Content-Security-Policy', CSP);
    res.sendFile(indexHtml);
  });

  app.use((req, res) => res.status(404).json({ codigo: 'ROTA_INEXISTENTE', erro: 'Rota inexistente.' }));

  // ---------- Erros ----------

  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    if (err?.type === 'entity.parse.failed' || err?.type === 'entity.too.large') {
      return res.status(400).json({ codigo: 'REQUISICAO_INVALIDA', erro: 'Requisição inválida.' });
    }
    if (err?.name?.startsWith('Mongo')) {
      log.error('[ANPRICE][BANCO]', { tipo: err.name });
      return erro(res, 503, 'BANCO_INDISPONIVEL');
    }
    log.error('[ANPRICE][ERRO_INTERNO]', { tipo: err?.name || 'Erro' });
    erro(res, 500, 'ERRO_INTERNO');
  });

  return app;
}

export async function criarIndices(db) {
  await db.collection('oauth_states').createIndex({ expires: 1 }, { expireAfterSeconds: 0 });
  await db.collection('sessions').createIndex({ expires: 1 }, { expireAfterSeconds: 0 });
  await db.collection('login_attempts').createIndex({ expires: 1 }, { expireAfterSeconds: 0 });
  await db.collection('login_attempts').createIndex({ ip: 1, at: 1 });
}
