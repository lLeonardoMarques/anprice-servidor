# AnPrice API — MongoDB Atlas — teste privado

Backend Node 20+ para uma conta e um administrador. MongoDB Atlas mantém sessões, autorização e tokens. Busca ampla é experimental: a API pode recusar com 403. O projeto não contorna restrições.

1. Segurança: use uma conta de banco dedicada ao AnPrice, com senha nova forte e privilégios mínimos. Não coloque URI ou senha no GitHub. A senha antes compartilhada deve ser trocada; considere efeitos em outros apps que usam a conta antiga.
2. Atlas: crie um usuário dedicado com leitura/escrita no banco `anprice`. Configure Network Access para permitir a saída do Render. Consulte seu plano: IPs de saída podem variar; liberar 0.0.0.0/0 abre acesso da rede a qualquer IP, use apenas se necessário e com senha forte e conta limitada, remova quando puder. Copie a string oficial do Atlas e substitua usuário e senha. Se tiver caracteres especiais, codifique-os na URI.
3. GitHub: crie repositório privado e envie o conteúdo desta pasta (package.json, server.js, .gitignore). Jamais envie .env.
4. Render: crie Web Service usando o repositório, runtime Node; Build Command `npm install`; Start Command `npm start`. Use uma única instância. Configure Environment:
- MONGO_URI: string segura de conexão do Atlas. O servidor usa o banco `anprice` no cluster independentemente do nome na URI; criará automaticamente as coleções ao primeiro uso, desde que o usuário tenha permissão.
- MELI_CLIENT_ID e MELI_CLIENT_SECRET: credenciais Mercado Livre.
- MELI_REDIRECT_URI: https://SEU-SERVICO.onrender.com/auth/mercadolivre/callback, com o serviço real.
- FRONTEND_URL: origem exata, ex. http://localhost:5173; GitHub Pages: https://USUARIO.github.io (sem caminho nem barra).
- ADMIN_PASSWORD: senha aleatória com pelo menos 16 caracteres.
- TOKEN_ENCRYPTION_KEY: gere com `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`. Guarde no Render; perder ou mudar a chave impede leitura dos tokens e exige reconexão.
- PORT é fornecida pelo Render; não é necessário ajustar.
5. Mercado Livre: registre exatamente a URI acima. Habilite Authorization Code, PKCE e refresh token / acesso offline, conforme disponíveis e suportados. Revise permissões.
6. Acesse /health e integre o frontend usando login POST /api/login {password}, GET /api/status, POST /api/auth/iniciar, GET /api/buscar?q=termo, POST /api/logout. Todas as chamadas autenticadas usam credentials: include; POSTs usam origem FRONTEND_URL. O login OAuth deve ser iniciado e concluído no mesmo navegador. Tokens não vão para o frontend.

O cookie é Secure/SameSite=None para domínios diferentes; navegadores que bloqueiam cookies de terceiros podem bloquear a sessão. O limitador de login e a trava de renovação são locais ao processo: execute apenas uma instância, não escalone nem use para venda sem autenticação, limitação distribuída e revisão de segurança adequadas. Em caso de falha entre renovação e gravação talvez seja preciso autorizar novamente. Banco requer acesso de escrita e criação de índices. Conta com acesso a outro banco não precisa ser apagada.
