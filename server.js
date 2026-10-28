
import express from 'express';
import { MongoClient } from 'mongodb';
import crypto from 'node:crypto';

// =============================================
// ANPRICE - BACKEND
// Login, MongoDB, OAuth e Mercado Livre
// =============================================

// 1. VARIAVEIS DE AMBIENTE

const required = [
  'MELI_CLIENT_ID',
  'MELI_CLIENT_SECRET',
  'MELI_REDIRECT_URI',
  'FRONTEND_URL',
  'MONGO_URI',
  'TOKEN_ENCRYPTION_KEY',
  'ADMIN_PASSWORD'
];

const missing = required.filter(k => !process.env[k]);

if (missing.length) {
  throw new Error(
    'Variaveis ausentes: ' + missing.join(', ')
  );
}

const keyHex = process.env.TOKEN_ENCRYPTION_KEY;

if (!/^[a-f0-9]{64}$/i.test(keyHex)) {
  throw new Error(
    'TOKEN_ENCRYPTION_KEY deve conter 64 caracteres hexadecimais'
  );
}

const key = Buffer.from(keyHex, 'hex');

if (process.env.ADMIN_PASSWORD.length < 16) {
  throw new Error(
    'ADMIN_PASSWORD deve ter ao menos 16 caracteres'
  );
}

// 2. BANCO DE DADOS

const mongo = new MongoClient(process.env.MONGO_URI);

await mongo.connect();

const db = mongo.db('anprice');

const tokens = db.collection('tokens');
const states = db.collection('oauth_states');
const sessions = db.collection('sessions');

await states.createIndex(
  { expires: 1 },
  { expireAfterSeconds: 0 }
);

await sessions.createIndex(
  { expires: 1 },
  { expireAfterSeconds: 0 }
);

// 3. EXPRESS E CORS

const app = express();

app.set('trust proxy', 1);
app.use(express.json({ limit: '4kb' }));

const origin = new URL(
  process.env.FRONTEND_URL
).origin;

app.use((req, res, next) => {
  if (req.headers.origin === origin) {
    res.set('Access-Control-Allow-Origin', origin);
    res.set('Vary', 'Origin');
    res.set('Access-Control-Allow-Credentials', 'true');
    res.set('Access-Control-Allow-Headers', 'Content-Type');
    res.set(
      'Access-Control-Allow-Methods',
      'GET, POST, OPTIONS'
    );
  }

  if (req.method === 'OPTIONS') {
    return res.sendStatus(
      req.headers.origin === origin ? 204 : 403
    );
  }

  next();
});

// 4. SEGURANCA E CRIPTOGRAFIA

const hash = s =>
  crypto
    .createHash('sha256')
    .update(s)
    .digest('hex');

const random = () =>
  crypto.randomBytes(32).toString('base64url');

function seal(obj) {
  const iv = crypto.randomBytes(12);

  const cipher = crypto.createCipheriv(
    'aes-256-gcm',
    key,
    iv
  );

  const data = Buffer.concat([
    cipher.update(JSON.stringify(obj), 'utf8'),
    cipher.final()
  ]);

  return [
    iv,
    cipher.getAuthTag(),
    data
  ]
    .map(b => b.toString('base64url'))
    .join('.');
}

function unseal(value) {
  const [iv, tag, data] = value
    .split('.')
    .map(x => Buffer.from(x, 'base64url'));

  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    key,
    iv
  );

  decipher.setAuthTag(tag);

  return JSON.parse(
    Buffer.concat([
      decipher.update(data),
      decipher.final()
    ]).toString()
  );
}

function sessionCookie(req) {
  const cookie = (req.headers.cookie || '')
    .split(';')
    .map(x => x.trim())
    .find(x => x.startsWith('anprice_session='));

  return cookie?.slice(
    'anprice_session='.length
  );
}

// 5. AUTENTICACAO ADMINISTRATIVA

async function auth(req, res, next) {
  try {
    const s = sessionCookie(req);

    if (!s) {
      return res.status(401).json({
        erro: 'Faça login de administrador.'
      });
    }

    const result = await sessions.findOne({
      _id: hash(s),
      expires: { $gt: new Date() }
    });

    if (!result) {
      return res.status(401).json({
        erro: 'Sessão expirada.'
      });
    }

    next();
  } catch {
    res.status(503).json({
      erro: 'Banco de dados indisponível.'
    });
  }
}

const cookieFlags =
  'HttpOnly; Secure; SameSite=None; Path=/; Max-Age=28800';

// 6. HEALTH CHECK

app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

// 7. LOGIN

let attempts = [];

app.post('/api/login', async (req, res, next) => {
  try {
    if (req.headers.origin !== origin) {
      return res.sendStatus(403);
    }

    attempts = attempts.filter(
      t => Date.now() - t < 60000
    );

    if (attempts.length >= 10) {
      return res.status(429).json({
        erro: 'Muitas tentativas. Aguarde um minuto.'
      });
    }

    attempts.push(Date.now());

    const supplied = Buffer.from(
      String(req.body?.password || '')
    );

    const expected = Buffer.from(
      process.env.ADMIN_PASSWORD
    );

    if (
      supplied.length !== expected.length ||
      !crypto.timingSafeEqual(supplied, expected)
    ) {
      return res.status(401).json({
        erro: 'Senha inválida.'
      });
    }

    const s = random();

    await sessions.insertOne({
      _id: hash(s),
      expires: new Date(
        Date.now() + 8 * 60 * 60 * 1000
      )
    });

    res.set(
      'Set-Cookie',
      `anprice_session=${s}; ${cookieFlags}`
    );

    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

// 8. LOGOUT

app.post(
  '/api/logout',
  auth,
  async (req, res, next) => {
    try {
      if (req.headers.origin !== origin) {
        return res.sendStatus(403);
      }

      await sessions.deleteOne({
        _id: hash(sessionCookie(req))
      });

      res.set(
        'Set-Cookie',
        'anprice_session=; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=0'
      );

      res.json({ ok: true });
    } catch (err) {
      next(err);
    }
  }
);

// 9. STATUS DA CONEXAO MERCADO LIVRE

app.get(
  '/api/status',
  auth,
  async (req, res, next) => {
    try {
      const result = await tokens.findOne({
        _id: 'principal'
      });

      res.json({
        conectado: !!result
      });
    } catch (err) {
      next(err);
    }
  }
);

// 10. INICIAR OAUTH

app.post(
  '/api/auth/iniciar',
  auth,
  async (req, res, next) => {
    try {
      if (req.headers.origin !== origin) {
        return res.sendStatus(403);
      }

      const state = random();
      const verifier = random();

      const challenge = crypto
        .createHash('sha256')
        .update(verifier)
        .digest('base64url');

      await states.insertOne({
        _id: hash(state),
        verifier: seal({ verifier }),
        sessionHash: hash(sessionCookie(req)),
        expires: new Date(
          Date.now() + 10 * 60 * 1000
        )
      });

      const url = new URL(
        'https://auth.mercadolivre.com.br/authorization'
      );

      const params = {
        response_type: 'code',
        client_id: process.env.MELI_CLIENT_ID,
        redirect_uri: process.env.MELI_REDIRECT_URI,
        state,
        code_challenge: challenge,
        code_challenge_method: 'S256'
      };

      for (const [k, v] of Object.entries(params)) {
        url.searchParams.set(k, v);
      }

      res.json({
        url: url.toString()
      });
    } catch (err) {
      next(err);
    }
  }
);

// 11. OBTER OU RENOVAR TOKENS OAUTH

async function oauth(params) {
  const resposta = await fetch(
    'https://api.mercadolibre.com/oauth/token',
    {
      method: 'POST',
      headers: {
        'Content-Type':
          'application/x-www-form-urlencoded',
        Accept: 'application/json'
      },
      body: new URLSearchParams({
        ...params,
        client_id: process.env.MELI_CLIENT_ID,
        client_secret: process.env.MELI_CLIENT_SECRET
      }),
      signal: AbortSignal.timeout(15000)
    }
  );

  if (!resposta.ok) {
    throw new Error('oauth_' + resposta.status);
  }

  const t = await resposta.json();

  if (
    !t.access_token ||
    !t.refresh_token ||
    !t.expires_in
  ) {
    throw new Error('oauth_response');
  }

  return {
    ...t,
    expires_at:
      Date.now() + Number(t.expires_in) * 1000
  };
}

// 12. CALLBACK DO MERCADO LIVRE

app.get(
  '/auth/mercadolivre/callback',
  auth,
  async (req, res) => {
    res.set('Cache-Control', 'no-store');

    try {
      const state = String(
        req.query.state || ''
      );

      const code = String(
        req.query.code || ''
      );

      if (!state || !code) {
        throw new Error('invalid');
      }

      const result = await states.findOneAndDelete({
        _id: hash(state),
        sessionHash: hash(sessionCookie(req)),
        expires: { $gt: new Date() }
      });

      if (!result) {
        throw new Error('state');
      }

      const verifier = unseal(
        result.verifier
      ).verifier;

      const t = await oauth({
        grant_type: 'authorization_code',
        code,
        redirect_uri:
          process.env.MELI_REDIRECT_URI,
        code_verifier: verifier
      });

      await tokens.replaceOne(
        { _id: 'principal' },
        {
          _id: 'principal',
          data: seal(t)
        },
        { upsert: true }
      );

      res.type('html').send(
        '<h2>Mercado Livre conectado.</h2>' +
        '<p>Feche esta janela e volte ao AnPrice.</p>'
      );
    } catch {
      res.status(400).type('html').send(
        '<h2>Não foi possível conectar.</h2>' +
        '<p>Inicie novamente a autorização e confira URI, permissões e PKCE.</p>'
      );
    }
  }
);

// 13. TOKEN ATIVO

let refreshInProgress = null;

async function token() {
  const row = await tokens.findOne({
    _id: 'principal'
  });

  if (!row) {
    throw new Error('not_connected');
  }

  const currentToken = unseal(row.data);

  if (
    Date.now() <
    currentToken.expires_at - 60000
  ) {
    return currentToken.access_token;
  }

  if (!refreshInProgress) {
    refreshInProgress = (async () => {
      const current = await tokens.findOne({
        _id: 'principal'
      });

      if (!current) {
        throw new Error('not_connected');
      }

      let value = unseal(current.data);

      if (
        Date.now() >=
        value.expires_at - 60000
      ) {
        value = await oauth({
          grant_type: 'refresh_token',
          refresh_token: value.refresh_token
        });

        await tokens.updateOne(
          { _id: 'principal' },
          {
            $set: {
              data: seal(value)
            }
          }
        );
      }

      return value.access_token;
    })().finally(() => {
      refreshInProgress = null;
    });
  }

  return refreshInProgress;
}

// =============================================
// 14. NOVA ROTA - DIAGNOSTICO DO TOKEN
// =============================================

// Temporaria: remover apos o diagnostico.
// Protegida pela mesma sessao de administrador.
// Nao retorna nem registra o token.

app.get(
  '/api/diagnostico/token',
  auth,
  async (req, res) => {
    res.set('Cache-Control', 'no-store');

    try {
      const access = await token();

      const resposta = await fetch(
        'https://api.mercadolibre.com/users/me',
        {
          method: 'GET',
          headers: {
            Authorization: `Bearer ${access}`,
            Accept: 'application/json'
          },
          signal: AbortSignal.timeout(15000)
        }
      );

      console.log('[ANPRICE][TOKEN_TEST]', {
        status: resposta.status,
        autorizado: resposta.ok
      });

      res.json({
        teste: 'users/me',
        statusMercadoLivre: resposta.status,
        autorizado: resposta.ok
      });
    } catch (err) {
      const notConnected =
        err?.message === 'not_connected';

      console.error('[ANPRICE][TOKEN_TEST]', {
        tipo: err?.name || 'UnknownError',
        codigo: notConnected
          ? 'NOT_CONNECTED'
          : 'VALIDATION_ERROR'
      });

      res.status(
        notConnected ? 409 : 503
      ).json({
        erro: notConnected
          ? 'Conecte o Mercado Livre primeiro.'
          : 'Nao foi possivel validar o acesso.'
      });
    }
  }
);

// =============================================
// 15. BUSCA DE PRODUTOS MERCADO LIVRE
// =============================================

app.get(
  '/api/buscar',
  auth,
  async (req, res) => {
    const q = String(
      req.query.q || ''
    ).trim();

    if (q.length < 2 || q.length > 100) {
      return res.status(400).json({
        erro:
          'Informe uma busca entre 2 e 100 caracteres.'
      });
    }

    try {
      const access = await token();

      const url = new URL(
        'https://api.mercadolibre.com/sites/MLB/search'
      );

      url.searchParams.set('q', q);
      url.searchParams.set('limit', '20');

      const resposta = await fetch(url, {
        headers: {
          Authorization: `Bearer ${access}`,
          Accept: 'application/json'
        },
        signal: AbortSignal.timeout(15000)
      });

      if (!resposta.ok) {
        let detail = {};

        try {
          const errorData = await resposta.json();

          if (
            errorData &&
            typeof errorData === 'object'
          ) {
            detail = {
              errorCode:
                typeof errorData.error === 'string'
                  ? errorData.error.slice(0, 100)
                  : null,

              policyCode:
                typeof errorData.code === 'string'
                  ? errorData.code.slice(0, 100)
                  : null,

              blockedBy:
                typeof errorData.blocked_by === 'string'
                  ? errorData.blocked_by.slice(0, 100)
                  : null,

              causeCodes:
                Array.isArray(errorData.cause)
                  ? errorData.cause
                      .slice(0, 5)
                      .map(c =>
                        c?.code != null
                          ? String(c.code).slice(0, 80)
                          : null
                      )
                  : []
            };
          }
        } catch {
          detail = {
            bodyFormat: 'non_json'
          };
        }

        console.error(
          '[ANPRICE][MELI_SEARCH]',
          {
            statusMercadoLivre:
              resposta.status,
            ...detail
          }
        );

        return res.status(
          resposta.status === 429 ? 429 : 502
        ).json({
          erro:
            'Consulta ao Mercado Livre não autorizada ou indisponível.',
          statusMercadoLivre:
            resposta.status,
          observacao:
            resposta.status === 403
              ? 'A API recusou a consulta por uma politica de acesso ou autorizacao.'
              : 'Verifique a disponibilidade e as permissoes da API.'
        });
      }

      const data = await resposta.json();

      res.json({
        consulta: q,
        consultadoEm:
          new Date().toISOString(),
        resultados: data.results || [],
        totalInformado:
          data.paging?.total ?? null
      });

    } catch (err) {
      const notConnected =
        err?.message === 'not_connected';

      console.error(
        '[ANPRICE][BUSCA_FALHOU]',
        {
          tipo:
            err?.name || 'UnknownError',
          codigo: notConnected
            ? 'NOT_CONNECTED'
            : 'UPSTREAM_OR_TOKEN_ERROR'
        }
      );

      res.status(503).json({
        erro: notConnected
          ? 'Conecte a conta do Mercado Livre primeiro.'
          : 'Não foi possível consultar. Confira a conexão e autorização.'
      });
    }
  }
);

// =============================================
// 16. TRATAMENTO GLOBAL DE ERROS
// =============================================

app.use((err, req, res, next) => {
  console.error(
    '[ANPRICE][ERRO_INTERNO]',
    {
      tipo: err?.name || 'UnknownError'
    }
  );

  res.status(500).json({
    erro: 'Erro interno.'
  });
});

// =============================================
// 17. INICIAR SERVIDOR
// =============================================

const PORT = Number(
  process.env.PORT || 3000
);

app.listen(
  PORT,
  '0.0.0.0',
  () => {
    console.log('AnPrice API iniciada');
    console.log(
      'Frontend autorizado:',
      origin
    );
  }
);
