# AnPrice — Servidor (API + frontend)

Servidor Node 20+ (Express 5 + MongoDB) que entrega o frontend AnPrice e a API **na mesma origem**.
Uso: um administrador e uma conta Mercado Livre.

## Arquitetura

```
Navegador ──► https://anprice-servidor.onrender.com
                ├─ /            frontend (repositório Anipro, compilado em web/dist no build)
                ├─ /api/...     login, status, busca, diagnóstico
                └─ /auth/mercadolivre/callback   retorno do OAuth
                         │
                         └──► api.mercadolibre.com (token guardado no MongoDB, criptografado)
```

- **Sessão:** cookie `anprice_session` `HttpOnly; Secure; SameSite=Lax`, 8 h, guardado no banco como hash SHA-256.
- **CSRF:** POSTs só são aceitos com `Origin` igual à origem do app; `SameSite=Lax` também barra POSTs entre sites.
- **OAuth:** Authorization Code + PKCE (S256). O callback é validado pelo `state` (256 bits, uso único, 10 min) e **não depende do cookie**.
- **Tokens:** AES-256-GCM no MongoDB. Refresh automático; se o Mercado Livre responder `invalid_grant`, o token é apagado e a interface pede reconexão.
- **Login:** limite de 10 falhas por IP e 30 no total a cada 15 min, gravado no MongoDB (sobrevive a reinícios).
- **Logs:** só códigos e status. Nunca tokens, senha, cookies ou Client Secret.

## Busca de produtos (mecanismos oficiais)

A busca ampla `/sites/MLB/search?q=` é recusada pelo Mercado Livre com `403 PolicyAgent`
para esta aplicação (confirmado: `/users/me` responde 200 com o mesmo token). Por isso `/api/buscar` usa:

1. `GET /products/search?status=active&site_id=MLB&q=` — produtos do catálogo;
2. `GET /products/{id}/items` — ofertas de cada produto (preço, vendedor, frete);
   se recusado, `GET /products/{id}` → `buy_box_winner`;
3. `GET /users/{id}` — apelido e reputação do vendedor (opcional);
4. se o catálogo for recusado ou vazio, tenta `/sites/MLB/search` uma vez.

Limitação: o catálogo cobre produtos catalogados, não todos os anúncios do site.

### Códigos de erro de `/api/*`

Toda resposta de erro tem `{ codigo, erro }`.

| HTTP | codigo | Significado |
| --- | --- | --- |
| 401 | `SESSAO_AUSENTE` / `SESSAO_EXPIRADA` | Login de administrador necessário |
| 403 | `ORIGEM_NAO_PERMITIDA` | POST de outra origem (CSRF) |
| 409 | `ML_NAO_CONECTADO` / `ML_REAUTORIZAR` / `ML_TOKEN_INVALIDO` | Conectar ou reconectar o Mercado Livre |
| 403 | `ML_BLOQUEADO_POLITICA` | Mercado Livre bloqueou o endpoint (PolicyAgent) — não é falha de infraestrutura |
| 403 | `ML_SEM_PERMISSAO` | Aplicação sem permissão para o recurso |
| 429 | `ML_LIMITE` / `LOGIN_LIMITE` | Limite de requisições |
| 502 / 504 | `ML_INDISPONIVEL` / `ML_TEMPO_ESGOTADO` | Falha real do Mercado Livre |
| 503 | `BANCO_INDISPONIVEL` | MongoDB fora do ar |

## Diagnóstico (temporário)

`GET /api/diagnostico/endpoints` (e o botão **Executar diagnóstico** no modal de configuração) testa
com o token salvo quais endpoints estão liberados e devolve só status e códigos.
Depois da investigação, defina `DIAGNOSTICO_ATIVO=false` no Render.

## Render

- **Build Command:** `npm run build` (instala o servidor, clona o repositório Anipro e compila o frontend em `web/`)
- **Start Command:** `npm start`
- **Instâncias:** 1 (a renovação de token e o cache de busca são locais ao processo)
- **Variáveis obrigatórias:** `MELI_CLIENT_ID`, `MELI_CLIENT_SECRET`, `MELI_REDIRECT_URI`, `MONGO_URI`,
  `TOKEN_ENCRYPTION_KEY` (64 hex), `ADMIN_PASSWORD` (16+ caracteres)
- **Opcionais:** `PUBLIC_URL` (padrão: origem de `MELI_REDIRECT_URI`), `DIAGNOSTICO_ATIVO`,
  `FRONTEND_REPO`, `FRONTEND_REF`
- `FRONTEND_URL` não é mais usada e pode ser removida.

Gerar `TOKEN_ENCRYPTION_KEY`: `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`.
Trocar essa chave invalida o token salvo e exige reconectar o Mercado Livre.

## Testes

```bash
npm install
npm test     # MongoDB e Mercado Livre simulados; não usa rede
```

Compilar o frontend a partir de uma pasta local (sem git clone):

```bash
WEB_SOURCE=../Meli node scripts/build-web.mjs
```
