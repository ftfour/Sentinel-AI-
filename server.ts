import 'dotenv/config';
import express from 'express';
import session from 'express-session';
import { createServer as createViteServer } from 'vite';
import { TelegramClient } from 'telegram';
import { StringSession } from 'telegram/sessions/index.js';
import { NewMessage } from 'telegram/events/index.js';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';

// Define a custom session type
declare module 'express-session' {
  interface SessionData {
    user?: {
      username: string;
      role: 'admin' | 'viewer';
    };
  }
}

const app = express();
const isProduction = process.env.NODE_ENV === 'production';
const PORT = Number(process.env.PORT ?? 3000);
const SESSION_SECRET = process.env.SESSION_SECRET ?? 'change-me-in-production';
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
type UserRole = 'admin' | 'viewer';
type UserStore = Record<string, { password: string; role: UserRole }>;

app.set('trust proxy', 1);
app.use(cors());
app.use(express.json());

// Session middleware
app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: isProduction,
      httpOnly: true,
      sameSite: 'lax',
      maxAge: 24 * 60 * 60 * 1000, // 1 day
    },
  })
);

// In-memory user store
const users: UserStore = {
  admin: { password: process.env.ADMIN_PASSWORD ?? '1q2w3e4r', role: 'admin' },
  viewer: { password: process.env.VIEWER_PASSWORD ?? '1234', role: 'viewer' },
};

let client: TelegramClient | null = null;
let isRunning = false;
let recentMessages: any[] = [];
let threatStats = { safe: 0, toxicity: 0, threat: 0, scam: 0 };
let targetChats: string[] = [];

// --- AUTH API ---
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const user = users[username as keyof typeof users];

  if (user && user.password === password) {
    req.session.user = { username, role: user.role };
    res.json({ username, role: user.role });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

app.post('/api/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ error: 'Could not log out' });
    }
    res.clearCookie('connect.sid'); // The default session cookie name
    res.json({ message: 'Logged out' });
  });
});

app.get('/api/user', (req, res) => {
  if (req.session.user) {
    res.json(req.session.user);
  } else {
    res.status(401).json({ error: 'Not authenticated' });
  }
});


const isAuthenticated = (req, res, next) => {
  if (req.session.user) {
    next();
  } else {
    res.status(401).json({ error: 'Not authenticated' });
  }
};

const isAdmin = (req, res, next) => {
  if (req.session.user && req.session.user.role === 'admin') {
    next();
  } else {
    res.status(403).json({ error: 'Forbidden' });
  }
};

async function analyzeThreat(text: string): Promise<{ type: string, score: number }> {
  if (!text || text.trim() === '') return { type: 'safe', score: 0.1 };
  return { type: 'safe', score: 0.1 };
}

app.post('/api/start', isAdmin, async (req, res) => {
  if (isRunning) return res.json({ status: 'already running' });
  
  const { apiId, apiHash, botToken, chats } = req.body;
  if (!apiId || !apiHash || !botToken) {
    return res.status(400).json({ error: 'API ID, API Hash, and Bot Token are required' });
  }

  targetChats = chats || targetChats;
  
  try {
    const stringSession = new StringSession('');
    client = new TelegramClient(stringSession, Number(apiId), apiHash, {
      connectionRetries: 5,
    });
    
    await client.start({
      botAuthToken: botToken,
    });
    
    isRunning = true;
    
    client.addEventHandler(async (event) => {
      const message = event.message;
      const text = message.text || '';
      
      const sender = await message.getSender();
      const senderName = sender && 'username' in sender && sender.username ? `@${sender.username}` : 'Unknown';
      
      const chat = await message.getChat();
      const chatTitle = chat && 'title' in chat ? chat.title : 'Unknown Chat';
      
      const analysis = await analyzeThreat(text);
      threatStats[analysis.type as keyof typeof threatStats]++;
      
      recentMessages.unshift({
        id: message.id,
        time: new Date(message.date * 1000).toLocaleTimeString(),
        chat: chatTitle,
        sender: senderName,
        text: text.substring(0, 100),
        type: analysis.type,
        score: analysis.score
      });
      
      if (recentMessages.length > 50) recentMessages.pop();
    }, new NewMessage({ chats: targetChats.length > 0 ? targetChats : undefined }));
    
    res.json({ status: 'started' });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/stop', isAdmin, async (req, res) => {
  if (client) {
    await client.disconnect();
    client = null;
    isRunning = false;
  }
  res.json({ status: 'stopped' });
});

app.get('/api/status', isAuthenticated, (req, res) => {
  res.json({ isRunning });
});

app.get('/api/messages', isAuthenticated, (req, res) => {
  res.json(recentMessages);
});

app.get('/api/stats', isAuthenticated, (req, res) => {
  res.json(threatStats);
});

async function startServer() {
  if (!isProduction) {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    if (SESSION_SECRET === 'change-me-in-production') {
      console.warn(
        'SESSION_SECRET is not configured. Set a strong value in .env for production.'
      );
    }

    const distDir = path.resolve(__dirname, 'dist');
    app.use(express.static(distDir));

    // SPA fallback for React Router routes like /login.
    app.get('*', (req, res, next) => {
      if (req.path.startsWith('/api')) {
        next();
        return;
      }
      res.sendFile(path.join(distDir, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
