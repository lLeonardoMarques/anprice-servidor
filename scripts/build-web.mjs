// Compila o frontend (repositório Anipro) dentro de web/ para que o
// servidor o entregue na mesma origem da API.
//
// Variáveis opcionais:
//   FRONTEND_REPO  URL git do frontend (padrão: repositório Anipro público)
//   FRONTEND_REF   branch ou tag (padrão: main)
//   WEB_SOURCE     pasta local do frontend (pula o git clone; útil em testes)

import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const raiz = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const destino = path.join(raiz, 'web');
const repo = process.env.FRONTEND_REPO || 'https://github.com/lLeonardoMarques/Anipro.git';
const ref = process.env.FRONTEND_REF || 'main';
const origemLocal = process.env.WEB_SOURCE;

const run = (cmd, args, cwd) => {
  console.log(`> ${cmd} ${args.join(' ')}`);
  execFileSync(cmd, args, { cwd, stdio: 'inherit', env: { ...process.env, NODE_ENV: 'development' } });
};

fs.rmSync(destino, { recursive: true, force: true });

if (origemLocal) {
  fs.cpSync(path.resolve(origemLocal), destino, {
    recursive: true,
    filter: src => !/[\\/](node_modules|dist|\.git)([\\/]|$)/.test(src)
  });
} else {
  run('git', ['clone', '--depth', '1', '--branch', ref, repo, destino], raiz);
}

run('npm', ['ci', '--include=dev', '--no-audit', '--no-fund'], destino);
run('npm', ['run', 'build'], destino);

if (!fs.existsSync(path.join(destino, 'dist', 'index.html'))) {
  throw new Error('Build do frontend não gerou dist/index.html');
}
console.log('Frontend compilado em web/dist');
