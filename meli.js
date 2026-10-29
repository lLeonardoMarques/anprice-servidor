// =============================================
// ANPRICE - CLIENTE DA API DO MERCADO LIVRE
// Classificação de erros e busca por mecanismos oficiais
// =============================================

// Erro tipado: o frontend decide a mensagem pelo `codigo`,
// nunca apenas pelo status HTTP.
export class MeliError extends Error {
  constructor(codigo, info = {}) {
    super(codigo);
    this.name = 'MeliError';
    this.codigo = codigo;
    this.statusMercadoLivre = info.statusMercadoLivre ?? null;
    this.politica = info.politica ?? null;
    this.endpoint = info.endpoint ?? null;
    this.tentativas = info.tentativas ?? null;
  }
}

// Status HTTP que o AnPrice devolve para cada código.
// 403 de política NÃO vira 502: é bloqueio de autorização,
// não indisponibilidade de infraestrutura.
export const HTTP_POR_CODIGO = {
  ML_NAO_CONECTADO: 409,
  ML_REAUTORIZAR: 409,
  ML_TOKEN_INVALIDO: 409,
  ML_BLOQUEADO_POLITICA: 403,
  ML_SEM_PERMISSAO: 403,
  ML_NAO_ENCONTRADO: 404,
  ML_LIMITE: 429,
  ML_TEMPO_ESGOTADO: 504,
  ML_INDISPONIVEL: 502,
  ML_OAUTH_FALHOU: 502,
  ML_RESPOSTA_INVALIDA: 502
};

const texto = (v, max = 100) =>
  typeof v === 'string' ? v.slice(0, max) : null;

// Converte uma resposta de erro do Mercado Livre em MeliError.
// Só lê campos técnicos (status, code, blocked_by, error).
export async function classificarResposta(resposta, endpoint) {
  let body = {};
  try {
    body = await resposta.json();
  } catch {
    body = {};
  }

  const status = resposta.status;
  const politica =
    texto(body?.blocked_by) === 'PolicyAgent'
      ? texto(body?.code) || 'POLICY_AGENT'
      : null;

  let codigo;
  if (status === 401) codigo = 'ML_TOKEN_INVALIDO';
  else if (status === 403) codigo = politica ? 'ML_BLOQUEADO_POLITICA' : 'ML_SEM_PERMISSAO';
  else if (status === 404) codigo = 'ML_NAO_ENCONTRADO';
  else if (status === 429) codigo = 'ML_LIMITE';
  else if (status >= 500) codigo = 'ML_INDISPONIVEL';
  else codigo = 'ML_RESPOSTA_INVALIDA';

  return new MeliError(codigo, {
    statusMercadoLivre: status,
    politica: politica || texto(body?.error, 60),
    endpoint
  });
}

export function createMeliClient({ fetchImpl, apiBase, getToken, timeoutMs = 15000 }) {
  async function requisitar(caminho, endpoint, access) {
    let resposta;
    try {
      resposta = await fetchImpl(apiBase + caminho, {
        headers: {
          Authorization: `Bearer ${access}`,
          Accept: 'application/json'
        },
        signal: AbortSignal.timeout(timeoutMs)
      });
    } catch (err) {
      const timeout = err?.name === 'TimeoutError' || err?.name === 'AbortError';
      throw new MeliError(timeout ? 'ML_TEMPO_ESGOTADO' : 'ML_INDISPONIVEL', { endpoint });
    }
    return resposta;
  }

  // `endpoint` é o modelo do caminho (sem IDs nem termos buscados),
  // usado em logs e diagnósticos.
  async function get(caminho, endpoint = caminho) {
    let access = await getToken();
    let resposta = await requisitar(caminho, endpoint, access);

    // 401 pode ser token expirado antes do previsto: renova uma vez.
    if (resposta.status === 401) {
      access = await getToken({ force: true });
      resposta = await requisitar(caminho, endpoint, access);
    }

    if (!resposta.ok) {
      throw await classificarResposta(resposta, endpoint);
    }

    try {
      return await resposta.json();
    } catch {
      throw new MeliError('ML_RESPOSTA_INVALIDA', { endpoint });
    }
  }

  // Igual a `get`, mas devolve só o status e o código (diagnóstico).
  async function sondar(caminho, endpoint) {
    try {
      const data = await get(caminho, endpoint);
      return { endpoint, status: 200, codigo: 'OK', data };
    } catch (err) {
      if (err instanceof MeliError) {
        return {
          endpoint,
          status: err.statusMercadoLivre,
          codigo: err.codigo,
          politica: err.politica
        };
      }
      throw err;
    }
  }

  return { get, sondar };
}

// Executa `fn` sobre `itens` com no máximo `limite` chamadas simultâneas.
export async function mapLimit(itens, limite, fn) {
  const resultados = new Array(itens.length);
  let proximo = 0;
  async function trabalhador() {
    while (proximo < itens.length) {
      const i = proximo++;
      resultados[i] = await fn(itens[i], i);
    }
  }
  await Promise.all(
    Array.from({ length: Math.min(limite, itens.length) }, trabalhador)
  );
  return resultados;
}

// Erros que interrompem a busca inteira (não adianta tentar outro produto).
const ERROS_FATAIS = [
  'ML_LIMITE',
  'ML_TOKEN_INVALIDO',
  'ML_REAUTORIZAR',
  'ML_NAO_CONECTADO',
  'ML_OAUTH_FALHOU'
];

const https = url => (typeof url === 'string' ? url.replace(/^http:\/\//, 'https://') : '');

// Converte uma oferta de catálogo no mesmo formato de item da busca
// do site, que o frontend já sabe exibir.
export function normalizarOferta(produto, oferta, vendedor) {
  const reputacao = vendedor?.seller_reputation || null;
  return {
    id: oferta.item_id,
    catalog_product_id: produto.id,
    title: produto.name,
    price: typeof oferta.price === 'number' ? oferta.price : null,
    original_price: typeof oferta.original_price === 'number' ? oferta.original_price : null,
    currency_id: oferta.currency_id || 'BRL',
    condition: oferta.condition || null,
    thumbnail: https(produto.pictures?.[0]?.url || produto.pictures?.[0]?.secure_url),
    permalink: `https://www.mercadolivre.com.br/p/${encodeURIComponent(produto.id)}`,
    official_store_id: oferta.official_store_id ?? null,
    listing_type_id: oferta.listing_type_id ?? null,
    shipping: {
      free_shipping: Boolean(oferta.shipping?.free_shipping),
      logistic_type: oferta.shipping?.logistic_type || null,
      mode: oferta.shipping?.mode || null
    },
    seller: {
      id: oferta.seller_id,
      nickname: vendedor?.nickname || null,
      seller_reputation: reputacao
        ? {
            level_id: reputacao.level_id || null,
            power_seller_status: reputacao.power_seller_status || null,
            metrics: {
              sales: { completed: reputacao.transactions?.completed ?? null }
            }
          }
        : null
    },
    address: {
      city_name: vendedor?.address?.city || null,
      state_name: vendedor?.address?.state || null
    },
    attributes: Array.isArray(produto.attributes)
      ? produto.attributes.slice(0, 15).map(a => ({
          id: a.id,
          name: a.name,
          value_name: a.value_name ?? null
        }))
      : [],
    sold_quantity: null,
    available_quantity: null,
    installments: null
  };
}

// Busca oficial em duas etapas:
//   1. /products/search  → produtos de catálogo para o termo
//   2. /products/{id}/items → ofertas (preço, vendedor, frete) de cada produto
// Se /products/{id}/items for recusado, usa o buy_box_winner de /products/{id}.
// Se o catálogo inteiro for recusado, tenta /sites/MLB/search uma vez.
export async function buscarProdutos(client, q, opcoes = {}) {
  const site = opcoes.site || 'MLB';
  const limiteProdutos = opcoes.limiteProdutos ?? 6;
  const limiteOfertas = opcoes.limiteOfertas ?? 10;
  const tentativas = [];

  const termo = encodeURIComponent(q);

  // Etapa 1: catálogo
  let catalogo;
  try {
    catalogo = await client.get(
      `/products/search?status=active&site_id=${site}&q=${termo}&limit=${limiteProdutos}`,
      '/products/search'
    );
    tentativas.push({ endpoint: '/products/search', codigo: 'OK' });
  } catch (err) {
    if (!(err instanceof MeliError)) throw err;
    tentativas.push({
      endpoint: '/products/search',
      codigo: err.codigo,
      status: err.statusMercadoLivre
    });
    if (!['ML_BLOQUEADO_POLITICA', 'ML_SEM_PERMISSAO', 'ML_NAO_ENCONTRADO'].includes(err.codigo)) {
      err.tentativas = tentativas;
      throw err;
    }
    return buscarNoSite(client, q, site, tentativas, err);
  }

  const produtos = (Array.isArray(catalogo?.results) ? catalogo.results : [])
    .filter(p => p && typeof p.id === 'string')
    .slice(0, limiteProdutos);

  // Catálogo sem produtos para o termo: a busca do site pode cobrir
  // anúncios fora do catálogo, se estiver liberada para esta aplicação.
  if (!produtos.length) {
    try {
      return await buscarNoSite(client, q, site, tentativas, null);
    } catch (err) {
      if (!(err instanceof MeliError) || ERROS_FATAIS.includes(err.codigo)) throw err;
      return { fonte: 'catalogo', resultados: [], totalInformado: 0, produtosConsultados: 0, tentativas };
    }
  }

  // Etapa 2: ofertas de cada produto
  const ofertasPorProduto = await mapLimit(produtos, 3, async produto => {
    const id = encodeURIComponent(produto.id);
    try {
      const r = await client.get(
        `/products/${id}/items?limit=${limiteOfertas}`,
        '/products/{id}/items'
      );
      return { produto, ofertas: Array.isArray(r?.results) ? r.results : [], origem: 'items' };
    } catch (err) {
      if (!(err instanceof MeliError)) throw err;
      if (ERROS_FATAIS.includes(err.codigo)) throw err;
      // Sem ofertas listáveis: tenta o vencedor da página do produto.
      try {
        const detalhe = await client.get(`/products/${id}`, '/products/{id}');
        const vencedor = detalhe?.buy_box_winner;
        return {
          produto: { ...produto, pictures: produto.pictures || detalhe?.pictures },
          ofertas: vencedor?.item_id ? [vencedor] : [],
          origem: 'buy_box_winner',
          erroItems: err.codigo
        };
      } catch (err2) {
        if (!(err2 instanceof MeliError)) throw err2;
        return { produto, ofertas: [], origem: 'nenhuma', erroItems: err.codigo };
      }
    }
  });

  const erros = ofertasPorProduto.filter(x => x.erroItems).map(x => x.erroItems);
  if (erros.length) {
    tentativas.push({
      endpoint: '/products/{id}/items',
      codigo: erros.every(c => c === erros[0]) ? erros[0] : 'VARIOS',
      falhas: erros.length,
      total: produtos.length
    });
  } else if (produtos.length) {
    tentativas.push({ endpoint: '/products/{id}/items', codigo: 'OK' });
  }

  // Etapa 3: dados públicos dos vendedores (opcional; falhas ignoradas)
  const idsVendedores = [
    ...new Set(
      ofertasPorProduto.flatMap(x => x.ofertas.map(o => o.seller_id)).filter(Boolean)
    )
  ].slice(0, 20);

  const vendedores = new Map();
  await mapLimit(idsVendedores, 4, async sellerId => {
    try {
      const u = await client.get(`/users/${encodeURIComponent(sellerId)}`, '/users/{id}');
      vendedores.set(sellerId, u);
    } catch (err) {
      if (!(err instanceof MeliError)) throw err;
    }
  });

  const resultados = ofertasPorProduto.flatMap(({ produto, ofertas }) =>
    ofertas
      .filter(o => o && o.item_id && typeof o.price === 'number')
      .map(o => normalizarOferta(produto, o, vendedores.get(o.seller_id)))
  );

  // Catálogo respondeu, mas nenhuma oferta pôde ser lida por bloqueio:
  // informa o bloqueio em vez de "nenhum resultado".
  if (!resultados.length && erros.length && erros.length === produtos.length) {
    const politica = erros.includes('ML_BLOQUEADO_POLITICA');
    throw new MeliError(politica ? 'ML_BLOQUEADO_POLITICA' : erros[0], {
      endpoint: '/products/{id}/items',
      tentativas
    });
  }

  return {
    fonte: 'catalogo',
    resultados,
    totalInformado: catalogo?.paging?.total ?? produtos.length,
    produtosConsultados: produtos.length,
    tentativas
  };
}

async function buscarNoSite(client, q, site, tentativas, erroCatalogo) {
  try {
    const data = await client.get(
      `/sites/${site}/search?q=${encodeURIComponent(q)}&limit=20`,
      '/sites/{site}/search'
    );
    tentativas.push({ endpoint: '/sites/{site}/search', codigo: 'OK' });
    return {
      fonte: 'busca_site',
      resultados: Array.isArray(data?.results) ? data.results : [],
      totalInformado: data?.paging?.total ?? null,
      tentativas
    };
  } catch (err) {
    if (!(err instanceof MeliError)) throw err;
    tentativas.push({
      endpoint: '/sites/{site}/search',
      codigo: err.codigo,
      status: err.statusMercadoLivre
    });
    // Reporta o erro mais informativo: política > permissão > o do catálogo.
    const candidatos = [erroCatalogo, err].filter(Boolean);
    const principal =
      candidatos.find(e => e.codigo === 'ML_BLOQUEADO_POLITICA') ||
      candidatos.find(e => e.codigo === 'ML_SEM_PERMISSAO') ||
      candidatos[0];
    principal.tentativas = tentativas;
    throw principal;
  }
}

// Extrai o ID de um link ou código de anúncio do Mercado Livre.
//   https://www.mercadolivre.com.br/.../p/MLB12345678      → produto de catálogo
//   https://produto.mercadolivre.com.br/MLB-1234567890-... → anúncio (item)
//   MLB1234567890                                          → indefinido (testa item, depois produto)
export function extrairReferencia(valor) {
  const s = String(valor || '').trim();
  if (!s || s.length > 1000) return null;
  const produto = s.match(/\/p\/(MLB\d{5,15})(?![\d])/i);
  if (produto) return { tipo: 'produto', id: produto[1].toUpperCase() };
  const item = s.match(/(?:^|[^A-Za-z0-9])MLB-?(\d{6,15})(?![\d])/i);
  if (item) return { tipo: /^https?:\/\//i.test(s) ? 'item' : 'indefinido', id: 'MLB' + item[1] };
  return null;
}

const naoTestado = endpoint => ({ endpoint, codigo: 'NAO_TESTADO' });

// Bateria de testes de acesso. Devolve apenas status e códigos.
// `ref` (opcional) é o resultado de extrairReferencia: permite testar as
// consultas por ID mesmo quando todas as buscas estão bloqueadas.
export async function diagnosticarEndpoints(client, { site = 'MLB', ref = null } = {}) {
  const termo = 'celular';
  const resultado = [];

  const me = await client.sondar('/users/me', '/users/me');
  resultado.push(me);

  const meId = me.data?.id;
  const PROPRIOS = '/users/{id}/items/search (seus anúncios)';
  resultado.push(
    meId != null
      ? await client.sondar(`/users/${encodeURIComponent(meId)}/items/search?limit=1`, PROPRIOS)
      : naoTestado(PROPRIOS)
  );

  resultado.push(
    await client.sondar(`/sites/${site}/search?q=${termo}&limit=1`, '/sites/{site}/search?q=')
  );

  resultado.push(
    await client.sondar(
      `/sites/${site}/domain_discovery/search?q=${termo}&limit=1`,
      '/sites/{site}/domain_discovery/search'
    )
  );

  const catalogo = await client.sondar(
    `/products/search?status=active&site_id=${site}&q=${termo}&limit=1`,
    '/products/search'
  );
  resultado.push(catalogo);

  let itemId = null;
  let sellerId = null;
  let itemSonda = null;
  let produtoDoItem = null;

  // Referência informada como anúncio (ou código ambíguo): testa /items/{id} primeiro.
  let produtoRef = ref?.tipo === 'produto' ? ref.id : null;
  if (ref && ref.tipo !== 'produto') {
    const s = await client.sondar(`/items/${encodeURIComponent(ref.id)}`, '/items/{id}');
    if (ref.tipo === 'indefinido' && s.codigo === 'ML_NAO_ENCONTRADO') {
      produtoRef = ref.id;
    } else {
      itemSonda = s;
      itemId = ref.id;
      sellerId = s.data?.seller_id ?? null;
      produtoDoItem = s.data?.catalog_product_id || null;
    }
  }

  const produtoId = produtoRef || produtoDoItem || catalogo.data?.results?.[0]?.id || null;

  if (produtoId) {
    const pid = encodeURIComponent(produtoId);
    const produto = await client.sondar(`/products/${pid}`, '/products/{id}');
    resultado.push(produto);
    const itens = await client.sondar(`/products/${pid}/items?limit=1`, '/products/{id}/items');
    resultado.push(itens);
    if (!itemId) {
      const primeira = itens.data?.results?.[0] || produto.data?.buy_box_winner;
      itemId = primeira?.item_id || null;
      sellerId = primeira?.seller_id || null;
    }
  } else {
    resultado.push(naoTestado('/products/{id}'));
    resultado.push(naoTestado('/products/{id}/items'));
  }

  if (itemId) {
    const iid = encodeURIComponent(itemId);
    resultado.push(itemSonda || (await client.sondar(`/items/${iid}`, '/items/{id}')));
    resultado.push(await client.sondar(`/items/${iid}/prices`, '/items/{id}/prices'));
  } else {
    resultado.push(naoTestado('/items/{id}'));
    resultado.push(naoTestado('/items/{id}/prices'));
  }

  resultado.push(
    sellerId != null
      ? await client.sondar(`/users/${encodeURIComponent(sellerId)}`, '/users/{id}')
      : naoTestado('/users/{id}')
  );

  // Remove os corpos das respostas: só status e códigos saem daqui.
  return resultado.map(({ data, ...r }) => ({
    endpoint: r.endpoint,
    status: r.status ?? null,
    codigo: r.codigo,
    politica: r.politica ?? null
  }));
}
