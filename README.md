# Sentinel AI RU

Sentinel AI RU is a full-stack monitoring dashboard prototype for Telegram messages.
The project combines:
- a React + Vite frontend,
- an Express backend API,
- a Telegram client listener (`telegram` package),
- session-based authentication.

The backend and frontend are served by a single Node.js process.

## Features

- Login with role-based access (`admin`, `viewer`)
- Start/stop Telegram monitoring from the UI
- Collect recent messages in memory
- Basic threat stats aggregation (`safe`, `toxicity`, `threat`, `scam`)
- Live dashboard UI with charts and logs

## Tech Stack

- Node.js + TypeScript
- Express + express-session + cors
- React 19 + react-router-dom
- Vite 6 + Tailwind CSS
- Telegram MTProto client (`telegram`)

## Project Structure

```text
.
|-- src/
|   |-- App.tsx
|   |-- LoginPage.tsx
|   |-- main.tsx
|   `-- index.css
|-- server.ts
|-- vite.config.ts
|-- package.json
`-- .env.example
```

## Requirements

- Node.js 22.x (recommended)
- npm 10+ (or compatible)

## Environment Variables

The repository ships with `.env.example`.

Current environment variables used in the project:

- `APP_URL` (from `.env.example`) - optional metadata URL.
- `NODE_ENV` - controls dev/prod mode in `server.ts`.

Important current behavior:
- The server port is currently hardcoded to `3000` in `server.ts`.
- Session secret is currently hardcoded in code and should be externalized before production use.

## Local Development

1. Install dependencies:

```bash
npm ci
```

2. Prepare environment file:

```bash
cp .env.example .env
```

3. Start development server:

```bash
npm run dev
```

4. Open:

```text
http://localhost:3000
```

## Build and Run (Production Mode)

1. Build frontend assets:

```bash
npm run build
```

2. Start server in production mode:

```bash
NODE_ENV=production npx tsx server.ts
```

The backend will serve static files from `dist/`.

## Available Scripts

- `npm run dev` - run full app in development mode (`tsx server.ts` + Vite middleware)
- `npm run build` - build frontend with Vite
- `npm run preview` - Vite preview for frontend bundle only
- `npm run lint` - TypeScript type check (`tsc --noEmit`)
- `npm run clean` - remove `dist` folder

## Authentication

The current implementation uses in-memory users defined in `server.ts`:

- `admin`
- `viewer`

Passwords are currently hardcoded in source code. Replace this with secure credential storage before any real deployment.

## API Endpoints

Auth:
- `POST /api/login`
- `POST /api/logout`
- `GET /api/user`

Engine:
- `POST /api/start` (admin only)
- `POST /api/stop` (admin only)
- `GET /api/status`
- `GET /api/messages`
- `GET /api/stats`

## Deployment Example (VPS with PM2 + Nginx)

1. Install runtime dependencies on server:

```bash
sudo apt update
sudo apt install -y curl git nginx build-essential
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt install -y nodejs
sudo npm i -g pm2
```

2. Deploy app:

```bash
git clone <your-repo-url> /opt/sentinel-ai-ru
cd /opt/sentinel-ai-ru
npm ci
npm run build
cp .env.example .env
NODE_ENV=production pm2 start "npx tsx server.ts" --name sentinel-ai-ru
pm2 save
pm2 startup
```

3. Configure Nginx reverse proxy to `http://127.0.0.1:3000`.

## Known Production Gaps

- `express-session` uses default `MemoryStore` (not suitable for production scale).
- Session secret is hardcoded.
- Demo users and passwords are hardcoded.
- Message and stats storage are in memory (data is lost on restart).
- `BrowserRouter` may require explicit SPA fallback handling for deep links.

## Recommended Next Steps

- Move secrets and credentials to environment variables.
- Replace memory session store with Redis or another persistent session backend.
- Add persistent database for users, messages, and stats.
- Add SPA fallback route in production static serving.
- Add Dockerfile and CI pipeline.

