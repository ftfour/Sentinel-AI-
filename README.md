# Sentinel AI RU

Sentinel AI RU is a full-stack Telegram monitoring dashboard prototype.
The app runs as a single Node.js process that serves:
- frontend (React + Vite),
- backend API (Express),
- Telegram listener control endpoints.

## Features

- Role-based login (`admin`, `viewer`)
- Start/stop monitoring from UI
- Recent messages and threat stats
- API for engine status and telemetry

## Stack

- Node.js 22 + TypeScript
- Express + express-session + cors
- React 19 + react-router-dom
- Vite 6 + Tailwind
- Telegram client (`telegram`)

## Structure

```text
.
|-- .github/workflows/deploy.yml
|-- ecosystem.config.cjs
|-- server.ts
|-- src/
|-- package.json
`-- .env.example
```

## Environment Variables

Create `.env` using `.env.example`.

- `NODE_ENV` - use `production` on server
- `PORT` - app port, default `3000`
- `SESSION_SECRET` - session cookie secret
- `ADMIN_PASSWORD` - password for `admin`
- `VIEWER_PASSWORD` - password for `viewer`
- `APP_URL` - optional app URL metadata

## Local Run

```bash
npm ci
cp .env.example .env
npm run dev
```

Open `http://localhost:3000`

## Manual Production Run

```bash
npm ci
npm run build
NODE_ENV=production npm run start
```

## NPM Scripts

- `npm run dev` - dev mode (`tsx server.ts` + Vite middleware)
- `npm run start` - server start (`tsx server.ts`)
- `npm run build` - frontend build to `dist`
- `npm run lint` - TypeScript type check
- `npm run preview` - Vite preview

## API

- `POST /api/login`
- `POST /api/logout`
- `GET /api/user`
- `POST /api/start` (admin only)
- `POST /api/stop` (admin only)
- `GET /api/status`
- `GET /api/messages`
- `GET /api/stats`

## Threat Models In Admin Panel

Admin panel now includes local ONNX model profiles:
- `local/rubert-tiny-balanced`
- `local/rubert-tiny-quantized`
- `local/rubert-tiny-fp16`

Message confidence percentages are calculated from model output (or heuristic fallback).
Models are downloaded once and cached in `.cache/models` on the server.

## Deploy From GitHub To Server

CI/CD workflow is implemented in [`.github/workflows/deploy.yml`](./.github/workflows/deploy.yml).

Flow:
1. Push to `main`
2. GitHub Actions builds project
3. Workflow connects to VPS over SSH
4. Runs `git pull`, `npm ci`, `npm run build`
5. Restarts app with PM2 (`pm2 startOrReload`)

### 1) One-Time Server Bootstrap (Ubuntu)

```bash
sudo apt update
sudo apt install -y curl git nginx build-essential
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt install -y nodejs
sudo npm i -g pm2
mkdir -p /opt/sentinel-ai-ru
```

### 2) Create `.env` On Server

```bash
cd /opt/sentinel-ai-ru
cp .env.example .env
nano .env
```

Required values:
- `SESSION_SECRET`
- `ADMIN_PASSWORD`
- `VIEWER_PASSWORD`
- optional `PORT`

### 3) Add GitHub Repository Secrets

Go to `Settings -> Secrets and variables -> Actions` and add:

- `DEPLOY_HOST` - server IP or domain
- `DEPLOY_USER` - SSH user
- `DEPLOY_SSH_KEY` - private SSH key (multiline)
- `DEPLOY_PORT` - SSH port (usually `22`)
- `APP_DIR` - app directory on server (example `/opt/sentinel-ai-ru`)

### 4) Trigger Deploy

- push to `main`, or
- run manually: `Actions -> Deploy To Server -> Run workflow`

## PM2

PM2 config: [`ecosystem.config.cjs`](./ecosystem.config.cjs)

Useful server commands:

```bash
pm2 status
pm2 logs sentinel-ai-ru
pm2 restart sentinel-ai-ru
pm2 save
```

## Nginx Reverse Proxy

```nginx
server {
  listen 80;
  server_name your-domain.com;

  location / {
    proxy_pass http://127.0.0.1:3000;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
  }
}
```

Apply config:

```bash
sudo nginx -t
sudo systemctl reload nginx
```

## Production Improvements Included

- `PORT` is read from env
- `SESSION_SECRET` is read from env
- secure cookies enabled in production
- SPA fallback for React routes is enabled
- auto deploy workflow from GitHub is added
