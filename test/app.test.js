import { test } from 'node:test';
import assert from 'node:assert/strict';
import { iniciar, tokenOk, json, POLICY_403, SENHA } from './helpers.js';
import { extrairReferencia } from '../meli.js';

// Catálogo do Mercado Livre simulado com 2 produtos e ofertas.
const catalogo = {
  '/oauth/token': tokenOk,
  '/users/me': () => json(200, { id: 1, nickname: 'TESTE' }),
  '/products/search': () =>
    json(200, {
      paging: { total: 2 },
      results: [
        { id: 'MLB111', name: 'Dior Sauvage EDT 100ml', pictures: [{ url: 'http://img.test/1.jpg' }], attributes: [{ id: 'BRAND', name: 'Marca', value_name: 'Dior' }] },
        { id: 'MLB222', name: 'Dior Sauvage EDP 60ml', pictures: [{ url: 'https://img.test/2.jpg' }] }
      ]
    }),
  '/products/MLB111/items': () =>
    json(200, {
      results: [
        { item_id: 'MLB9001', price: 650, currency_id: 'BRL', condition: 'new', seller_id: 77, shipping: { free_shipping: true, logistic_type: 'fulfillment' } },
        { item_id: 'MLB9002', price: 599.9, currency_id: 'BRL', condition: 'new', seller_id: 88, shipping: { free_shipping: false } }
      ]
    }),
  '/products/MLB222/items': () => json(403, POLICY_403),
  '/products/MLB222': () =>
    json(200, { id: 'MLB222', buy_box_winner: { item_id: 'MLB9003', price: 480, currency_id: 'BRL', seller_id: 77, condition: 'new', shipping: {} } }),
  '/users/77': () => json(200, { id: 77, nickname: 'LOJA_A', seller_reputation: { level_id: '5_green', power_seller_status: 'platinum', transactions: { completed: 1200 } }, address: { city: 'São Paulo', state: 'BR-SP' } }),
  '/users/88': () => json(403, POLICY_403),
  '/sites/MLB/search': () => json(403, POLICY_403)
};

test('login: senha errada, limite por IP no banco e cookie Lax', async t => {
  const s = await iniciar();
  t.after(s.close);

  const errado = await s.req('/api/login', { method: 'POST', body: { password: 'x' } });
  assert.equal(errado.status, 401);
  assert.equal(errado.dados.codigo, 'SENHA_INVALIDA');

  const ok = await s.req('/api/login', { method: 'POST', body: { password: SENHA } });
  assert.equal(ok.status, 200);
  assert.match(ok.setCookie, /HttpOnly; Secure; SameSite=Lax; Path=\//);
  assert.doesNotMatch(ok.setCookie, /SameSite=None/);
  assert.equal(await s.db.collection('login_attempts').countDocuments({}), 0, 'sucesso limpa as falhas do IP');

  for (let i = 0; i < 10; i++) {
    await s.req('/api/login', { method: 'POST', body: { password: 'errada' } });
  }
  const bloqueado = await s.req('/api/login', { method: 'POST', body: { password: SENHA } });
  assert.equal(bloqueado.status, 429);
  assert.equal(bloqueado.dados.codigo, 'LOGIN_LIMITE');
});

test('CSRF: POST de outra origem é recusado com código próprio (não "senha incorreta")', async t => {
  const s = await iniciar();
  t.after(s.close);
  const r = await s.req('/api/login', { method: 'POST', body: { password: SENHA }, origin: 'https://evil.test' });
  assert.equal(r.status, 403);
  assert.equal(r.dados.codigo, 'ORIGEM_NAO_PERMITIDA');
  const semOrigem = await s.req('/api/login', { method: 'POST', body: { password: SENHA }, origin: null });
  assert.equal(semOrigem.status, 403);
});

test('sessão: ausente, válida e encerrada', async t => {
  const s = await iniciar();
  t.after(s.close);
  assert.equal((await s.req('/api/status')).dados.codigo, 'SESSAO_AUSENTE');
  await s.login();
  const st = await s.req('/api/status');
  assert.equal(st.status, 200);
  assert.equal(st.dados.conectado, false);
  await s.req('/api/logout', { method: 'POST' });
  assert.equal((await s.req('/api/status')).status, 401);
});

test('OAuth: callback funciona sem cookie (só state + PKCE) e o state é de uso único', async t => {
  const s = await iniciar({ rotas: catalogo });
  t.after(s.close);
  await s.login();

  const iniciarResp = await s.req('/api/auth/iniciar', { method: 'POST' });
  const url = new URL(iniciarResp.dados.url);
  assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
  const state = url.searchParams.get('state');

  const cb = await s.req(`/auth/mercadolivre/callback?code=C&state=${state}`, { semCookie: true });
  assert.equal(cb.status, 303);
  assert.equal(cb.headers.get('location'), '/?ml=conectado');

  const troca = s.meli.chamadas.find(c => c.caminho === '/oauth/token');
  const corpo = new URLSearchParams(troca.init.body);
  assert.equal(corpo.get('grant_type'), 'authorization_code');
  assert.ok(corpo.get('code_verifier'), 'PKCE verifier enviado');

  const repetido = await s.req(`/auth/mercadolivre/callback?code=C&state=${state}`, { semCookie: true });
  assert.equal(repetido.headers.get('location'), '/?ml=erro&motivo=STATE_INVALIDO');

  const negado = await s.req('/auth/mercadolivre/callback?error=access_denied', { semCookie: true });
  assert.equal(negado.headers.get('location'), '/?ml=erro&motivo=AUTORIZACAO_NEGADA');

  assert.equal((await s.req('/api/status')).dados.conectado, true);

  const row = await s.db.collection('tokens').findOne({ _id: 'principal' });
  assert.doesNotMatch(row.data, /AT-|RT-1/, 'token gravado criptografado');
});

test('busca: catálogo oficial com ofertas, buy_box_winner e vendedores', async t => {
  const s = await iniciar({ rotas: catalogo });
  t.after(s.close);
  await s.login();
  await s.conectar();

  const r = await s.req('/api/buscar?q=Dior%20Sauvage');
  assert.equal(r.status, 200);
  assert.equal(r.dados.fonte, 'catalogo');
  assert.equal(r.dados.resultados.length, 3);

  const [a, b, c] = r.dados.resultados;
  assert.equal(a.id, 'MLB9001');
  assert.equal(a.title, 'Dior Sauvage EDT 100ml');
  assert.equal(a.thumbnail, 'https://img.test/1.jpg');
  assert.equal(a.seller.nickname, 'LOJA_A');
  assert.equal(a.seller.seller_reputation.level_id, '5_green');
  assert.equal(a.shipping.logistic_type, 'fulfillment');
  assert.equal(a.permalink, 'https://www.mercadolivre.com.br/p/MLB111');
  assert.equal(b.seller.nickname, null, 'vendedor bloqueado não derruba a busca');
  assert.equal(c.id, 'MLB9003', 'oferta vencedora usada quando /items é bloqueado');

  // Busca do site não é chamada quando o catálogo funciona.
  assert.ok(!s.meli.chamadas.some(x => x.caminho.startsWith('/sites/MLB/search')));
  const enviado = s.meli.chamadas.find(x => x.caminho.startsWith('/products/search'));
  assert.match(enviado.init.headers.Authorization, /^Bearer AT-/);

  // Cache: segunda busca não chama o Mercado Livre.
  const n = s.meli.chamadas.length;
  const r2 = await s.req('/api/buscar?q=dior%20sauvage');
  assert.equal(r2.dados.cache, true);
  assert.equal(s.meli.chamadas.length, n);
});

test('busca: PolicyAgent em todos os caminhos vira 403 ML_BLOQUEADO_POLITICA (não 502)', async t => {
  const s = await iniciar({
    rotas: { ...catalogo, '/products/search': () => json(403, POLICY_403) }
  });
  t.after(s.close);
  await s.login();
  await s.conectar();

  const r = await s.req('/api/buscar?q=Dior');
  assert.equal(r.status, 403);
  assert.equal(r.dados.codigo, 'ML_BLOQUEADO_POLITICA');
  assert.equal(r.dados.politica, 'PA_UNAUTHORIZED_RESULT_FROM_POLICIES');
  assert.deepEqual(
    r.dados.tentativas.map(x => x.endpoint),
    ['/products/search', '/sites/{site}/search']
  );
});

test('busca: catálogo bloqueado mas busca do site liberada → usa a busca do site', async t => {
  const s = await iniciar({
    rotas: {
      ...catalogo,
      '/products/search': () => json(403, POLICY_403),
      '/sites/MLB/search': () => json(200, { paging: { total: 1 }, results: [{ id: 'MLB5', title: 'X', price: 10 }] })
    }
  });
  t.after(s.close);
  await s.login();
  await s.conectar();
  const r = await s.req('/api/buscar?q=Dior');
  assert.equal(r.status, 200);
  assert.equal(r.dados.fonte, 'busca_site');
  assert.equal(r.dados.resultados[0].id, 'MLB5');
});

test('erros distintos: não conectado, limite, indisponível, tempo esgotado', async t => {
  const s = await iniciar({ rotas: catalogo });
  t.after(s.close);
  await s.login();

  const naoConectado = await s.req('/api/buscar?q=Dior');
  assert.equal(naoConectado.status, 409);
  assert.equal(naoConectado.dados.codigo, 'ML_NAO_CONECTADO');

  await s.conectar();
  const casos = [
    [() => json(429, {}), 429, 'ML_LIMITE'],
    [() => json(500, {}), 502, 'ML_INDISPONIVEL'],
    [() => { throw Object.assign(new Error('t'), { name: 'TimeoutError' }); }, 504, 'ML_TEMPO_ESGOTADO']
  ];
  for (const [i, [rota, status, codigo]] of casos.entries()) {
    const s2 = await iniciar({ rotas: { ...catalogo, '/products/search': rota } });
    t.after(s2.close);
    await s2.login();
    await s2.conectar();
    const r = await s2.req('/api/buscar?q=termo' + i);
    assert.equal(r.status, status, codigo);
    assert.equal(r.dados.codigo, codigo);
  }
});

test('token: refresh invalid_grant apaga o token e pede reconexão', async t => {
  let trocas = 0;
  const s = await iniciar({
    rotas: {
      ...catalogo,
      '/oauth/token': (u, init) => {
        trocas++;
        const corpo = new URLSearchParams(init.body);
        if (corpo.get('grant_type') === 'refresh_token') return json(400, { error: 'invalid_grant' });
        return json(200, { access_token: 'AT-x', refresh_token: 'RT-x', expires_in: 1 });
      }
    }
  });
  t.after(s.close);
  await s.login();
  await s.conectar(); // expires_in=1s → já nasce vencido pela margem de 60s

  const r = await s.req('/api/buscar?q=Dior');
  assert.equal(r.status, 409);
  assert.equal(r.dados.codigo, 'ML_REAUTORIZAR');
  assert.equal(trocas, 2);
  assert.equal((await s.req('/api/status')).dados.conectado, false);
});

test('diagnóstico de endpoints devolve só status e códigos, e pode ser desligado', async t => {
  const s = await iniciar({
    rotas: {
      ...catalogo,
      '/products/search': () => json(200, { results: [{ id: 'MLB111' }] }),
      '/items/MLB9001': () => json(200, { id: 'MLB9001', title: 'segredo?' })
    }
  });
  t.after(s.close);
  await s.login();
  await s.conectar();

  const r = await s.req('/api/diagnostico/endpoints');
  assert.equal(r.status, 200);
  const mapa = Object.fromEntries(r.dados.resultados.map(x => [x.endpoint, x.codigo]));
  assert.equal(mapa['/users/me'], 'OK');
  assert.equal(mapa['/sites/{site}/search?q='], 'ML_BLOQUEADO_POLITICA');
  assert.equal(mapa['/products/search'], 'OK');
  assert.equal(mapa['/products/{id}/items'], 'OK');
  assert.equal(mapa['/items/{id}'], 'OK');
  assert.doesNotMatch(JSON.stringify(r.dados), /segredo|LOJA_A|Bearer|AT-/);

  const tk = await s.req('/api/diagnostico/token');
  assert.equal(tk.dados.autorizado, true);

  const off = await iniciar({ config: { diagnosticoAtivo: false } });
  t.after(off.close);
  await off.login();
  assert.equal((await off.req('/api/diagnostico/endpoints')).status, 404);
});

test('logs nunca contêm tokens, senha ou segredo do cliente', async t => {
  const s = await iniciar({ rotas: { ...catalogo, '/products/search': () => json(403, POLICY_403) } });
  t.after(s.close);
  await s.req('/api/login', { method: 'POST', body: { password: 'errada' } });
  await s.login();
  await s.conectar();
  await s.req('/api/buscar?q=Dior');
  await s.req('/api/diagnostico/endpoints');
  const tudo = JSON.stringify(s.logs);
  assert.doesNotMatch(tudo, /AT-|RT-1|client-secret-teste|senha-de-teste|anprice_session=/);
  assert.match(tudo, /PA_UNAUTHORIZED_RESULT_FROM_POLICIES/, 'código da política é registrado');
});

test('frontend servido na mesma origem com CSP; /api desconhecida é 404 JSON', async t => {
  const s = await iniciar({ comFrontend: true });
  t.after(s.close);
  const home = await s.req('/');
  assert.equal(home.status, 200);
  assert.match(home.dados, /id="root"/);
  assert.match(home.headers.get('content-security-policy'), /default-src 'self'/);
  assert.equal(home.headers.get('x-frame-options'), 'DENY');

  const spa = await s.req('/qualquer/rota');
  assert.match(spa.dados, /id="root"/);

  const asset = await s.req('/assets/app.js');
  assert.match(asset.headers.get('cache-control'), /immutable/);

  const api = await s.req('/api/nao-existe');
  assert.equal(api.status, 404);
  assert.equal(api.dados.codigo, 'ROTA_INEXISTENTE');
  assert.equal(api.headers.get('cache-control'), 'no-store');
});

test('sem frontend compilado o servidor responde 503 explicativo', async t => {
  const s = await iniciar();
  t.after(s.close);
  const r = await s.req('/');
  assert.equal(r.status, 503);
  assert.match(r.dados, /npm run build/);
});

test('extrairReferencia: links de produto, de anúncio e códigos', () => {
  assert.deepEqual(
    extrairReferencia('https://www.mercadolivre.com.br/perfume-dior-sauvage-edt-100ml/p/MLB15184521?pdp_filters=item_id:MLB3333'),
    { tipo: 'produto', id: 'MLB15184521' }
  );
  assert.deepEqual(
    extrairReferencia('https://produto.mercadolivre.com.br/MLB-4012345678-perfume-dior-_JM#position=1'),
    { tipo: 'item', id: 'MLB4012345678' }
  );
  assert.deepEqual(extrairReferencia(' mlb4012345678 '), { tipo: 'indefinido', id: 'MLB4012345678' });
  assert.equal(extrairReferencia('https://www.google.com'), null);
  assert.equal(extrairReferencia(''), null);
});

test('diagnóstico com link de anúncio testa as consultas por ID mesmo com a busca bloqueada', async t => {
  const s = await iniciar({
    rotas: {
      ...catalogo,
      '/products/search': () => json(403, POLICY_403),
      '/sites/MLB/domain_discovery': () => json(403, POLICY_403),
      '/users/1/items/search': () => json(200, { results: [] }),
      '/products/MLB111': () => json(200, { id: 'MLB111' }),
      '/products/MLB15184521': () => json(200, { id: 'MLB15184521' }),
      '/items/MLB4012345678/prices': () => json(403, POLICY_403),
      '/items/MLB4012345678': () => json(200, { id: 'MLB4012345678', seller_id: 77, catalog_product_id: 'MLB111' })
    }
  });
  t.after(s.close);
  await s.login();
  await s.conectar();

  const ruim = await s.req('/api/diagnostico/endpoints?ref=' + encodeURIComponent('https://www.google.com'));
  assert.equal(ruim.status, 400);
  assert.equal(ruim.dados.codigo, 'REFERENCIA_INVALIDA');

  const link = 'https://produto.mercadolivre.com.br/MLB-4012345678-perfume-dior-_JM';
  const r = await s.req('/api/diagnostico/endpoints?ref=' + encodeURIComponent(link));
  assert.equal(r.status, 200);
  assert.deepEqual(r.dados.referencia, { tipo: 'item', id: 'MLB4012345678' });
  const mapa = Object.fromEntries(r.dados.resultados.map(x => [x.endpoint, x.codigo]));
  assert.equal(mapa['/users/{id}/items/search (seus anúncios)'], 'OK');
  assert.equal(mapa['/products/search'], 'ML_BLOQUEADO_POLITICA');
  assert.equal(mapa['/items/{id}'], 'OK');
  assert.equal(mapa['/items/{id}/prices'], 'ML_BLOQUEADO_POLITICA');
  assert.equal(mapa['/products/{id}'], 'OK', 'produto de catálogo obtido a partir do anúncio');
  assert.equal(mapa['/products/{id}/items'], 'OK');
  assert.equal(mapa['/users/{id}'], 'OK');
  assert.ok(!Object.values(mapa).includes('NAO_TESTADO'));

  // Código ambíguo que não é anúncio → testado como produto de catálogo.
  const r2 = await s.req('/api/diagnostico/endpoints?ref=MLB15184521');
  assert.deepEqual(r2.dados.referencia, { tipo: 'indefinido', id: 'MLB15184521' });
  const mapa2 = Object.fromEntries(r2.dados.resultados.map(x => [x.endpoint, x.codigo]));
  assert.equal(mapa2['/products/{id}'], 'OK');
});
