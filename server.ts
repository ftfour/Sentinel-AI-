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
type ThreatType = 'safe' | 'toxicity' | 'threat' | 'scam';
type RiskCategory = Exclude<ThreatType, 'safe'>;
type RiskScores = Record<RiskCategory, number>;
type LabelScore = { label: string; score: number };

type ThreatModelConfig = {
  id: string;
  name: string;
  description: string;
  labelHints: {
    toxicity: string[];
    threat: string[];
    scam: string[];
  };
};

const HF_API_TOKEN = process.env.HF_API_TOKEN ?? process.env.HUGGINGFACE_API_TOKEN ?? '';
const MODEL_CONFIGS: Record<string, ThreatModelConfig> = {
  'cointegrated/rubert-tiny-toxicity': {
    id: 'cointegrated/rubert-tiny-toxicity',
    name: 'RuBERT Tiny Toxicity',
    description: 'Fast toxicity model for Russian text.',
    labelHints: {
      toxicity: ['toxic', 'toxicity', 'insult', 'obscene', 'abuse', 'hate', 'offensive'],
      threat: ['threat', 'violence', 'kill'],
      scam: ['fraud', 'scam', 'phishing'],
    },
  },
  's-nlp/russian_toxicity_classifier': {
    id: 's-nlp/russian_toxicity_classifier',
    name: 'Russian Toxicity Classifier',
    description: 'Binary toxic vs non-toxic model for Russian text.',
    labelHints: {
      toxicity: ['toxic', 'toxicity', 'label_1'],
      threat: ['threat', 'violence'],
      scam: ['fraud', 'scam'],
    },
  },
  'apanc/russian-sensitive-topics': {
    id: 'apanc/russian-sensitive-topics',
    name: 'Russian Sensitive Topics',
    description: 'Sensitive topic classifier for risky domains.',
    labelHints: {
      toxicity: ['hate', 'racism', 'sexism', 'harassment', 'porn', 'obscene'],
      threat: ['terror', 'extrem', 'war', 'weapon', 'violence', 'crime', 'drugs', 'suicide'],
      scam: ['fraud', 'scam', 'phishing', 'ponzi', 'gambling', 'spam', 'crypto'],
    },
  },
};
const DEFAULT_MODEL_ID = 'cointegrated/rubert-tiny-toxicity';
const HEURISTIC_PATTERNS: Record<RiskCategory, RegExp[]> = {
  toxicity: [
    /идиот/i,
    /дебил/i,
    /твар/i,
    /урод/i,
    /ненавиж/i,
    /оскорб/i,
    /мат/i,
  ],
  threat: [
    /убью/i,
    /взорв/i,
    /расстрел/i,
    /зареж/i,
    /бомб/i,
    /оруж/i,
    /террор/i,
    /смерт/i,
  ],
  scam: [
    /быст(рый|ро) доход/i,
    /инвест/i,
    /крипт/i,
    /перевед(и|ите)/i,
    /seed phrase/i,
    /кошел[её]к/i,
    /cvv/i,
    /предоплат/i,
    /выигрыш/i,
    /гарантированн/i,
  ],
};

let selectedModelId = DEFAULT_MODEL_ID;
let threatThreshold = 0.75;

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

function emptyRiskScores(): RiskScores {
  return { toxicity: 0, threat: 0, scam: 0 };
}

function clamp01(value: number): number {
  if (!Number.isFinite(value)) return 0;
  if (value < 0) return 0;
  if (value > 1) return 1;
  return value;
}

function normalizeThreshold(value: unknown): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return threatThreshold;
  }
  const normalized = value > 1 ? value / 100 : value;
  return Math.min(0.99, Math.max(0.01, normalized));
}

function normalizeLabelScores(payload: unknown): LabelScore[] {
  if (!payload) return [];

  let candidates: unknown[] = [];
  if (Array.isArray(payload)) {
    if (payload.length > 0 && Array.isArray(payload[0])) {
      candidates = payload[0] as unknown[];
    } else {
      candidates = payload as unknown[];
    }
  } else if (typeof payload === 'object') {
    const candidate = payload as Record<string, unknown>;
    if (typeof candidate.label === 'string' && typeof candidate.score === 'number') {
      candidates = [candidate];
    } else {
      return [];
    }
  } else {
    return [];
  }

  return candidates
    .filter((item) => typeof item === 'object' && item !== null)
    .map((item) => {
      const entry = item as Record<string, unknown>;
      return {
        label: String(entry.label ?? ''),
        score: clamp01(Number(entry.score ?? 0)),
      };
    })
    .filter((entry) => entry.label.length > 0);
}

function matchesAnyHint(label: string, hints: string[]): boolean {
  return hints.some((hint) => label.includes(hint));
}

function extractModelScores(modelId: string, labels: LabelScore[]): RiskScores {
  const scores = emptyRiskScores();
  const config = MODEL_CONFIGS[modelId] ?? MODEL_CONFIGS[DEFAULT_MODEL_ID];

  for (const { label: rawLabel, score } of labels) {
    const label = rawLabel.toLowerCase();

    if (matchesAnyHint(label, config.labelHints.toxicity)) {
      scores.toxicity = Math.max(scores.toxicity, score);
    }
    if (matchesAnyHint(label, config.labelHints.threat)) {
      scores.threat = Math.max(scores.threat, score);
    }
    if (matchesAnyHint(label, config.labelHints.scam)) {
      scores.scam = Math.max(scores.scam, score);
    }
  }

  return scores;
}

function heuristicScores(text: string): RiskScores {
  const scores = emptyRiskScores();

  (Object.keys(HEURISTIC_PATTERNS) as RiskCategory[]).forEach((category) => {
    const hits = HEURISTIC_PATTERNS[category].reduce((sum, pattern) => sum + (pattern.test(text) ? 1 : 0), 0);
    scores[category] = clamp01(Math.min(0.92, hits * 0.22));
  });

  if (/https?:\/\//i.test(text) && /(перевод|оплат|кошел|card|wallet|крипт|btc|usdt)/i.test(text)) {
    scores.scam = Math.max(scores.scam, 0.7);
  }

  return scores;
}

async function requestModelScores(modelId: string, text: string): Promise<RiskScores> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 12000);

  try {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };
    if (HF_API_TOKEN) {
      headers.Authorization = `Bearer ${HF_API_TOKEN}`;
    }

    const response = await fetch(`https://api-inference.huggingface.co/models/${modelId}`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        inputs: text.slice(0, 1000),
        options: { wait_for_model: true },
      }),
      signal: controller.signal,
    });

    const payload = await response.json();
    if (!response.ok) {
      const errorMessage =
        typeof payload?.error === 'string'
          ? payload.error
          : `Inference request failed with status ${response.status}`;
      throw new Error(errorMessage);
    }

    const labels = normalizeLabelScores(payload);
    return extractModelScores(modelId, labels);
  } finally {
    clearTimeout(timeoutId);
  }
}

async function analyzeThreat(text: string): Promise<{ type: ThreatType; score: number }> {
  if (!text || text.trim() === '') {
    return { type: 'safe', score: 0.99 };
  }

  const normalizedText = text.trim();
  const heuristic = heuristicScores(normalizedText);
  let model = emptyRiskScores();

  try {
    model = await requestModelScores(selectedModelId, normalizedText);
  } catch (error) {
    console.warn(`Inference fallback to heuristics: ${(error as Error).message}`);
  }

  const combined: RiskScores = {
    toxicity: Math.max(heuristic.toxicity, model.toxicity),
    threat: Math.max(heuristic.threat, model.threat),
    scam: Math.max(heuristic.scam, model.scam),
  };

  const ranked = (Object.entries(combined) as [RiskCategory, number][])
    .sort((a, b) => b[1] - a[1]);
  const [topCategory, topScore] = ranked[0];

  if (topScore >= threatThreshold) {
    return { type: topCategory, score: clamp01(topScore) };
  }

  const safeConfidence = clamp01(Math.max(0.05, 1 - topScore));
  return { type: 'safe', score: safeConfidence };
}

app.post('/api/start', isAdmin, async (req, res) => {
  if (isRunning) return res.json({ status: 'already running' });
  
  const { apiId, apiHash, botToken, chats, model, threatThreshold: requestedThreshold } = req.body;
  if (!apiId || !apiHash || !botToken) {
    return res.status(400).json({ error: 'API ID, API Hash, and Bot Token are required' });
  }

  targetChats = chats || targetChats;
  selectedModelId = typeof model === 'string' && MODEL_CONFIGS[model] ? model : DEFAULT_MODEL_ID;
  threatThreshold = normalizeThreshold(requestedThreshold);
  
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
    
    res.json({
      status: 'started',
      model: selectedModelId,
      threshold: threatThreshold,
      usingHfToken: Boolean(HF_API_TOKEN),
    });
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
  res.json({
    isRunning,
    model: selectedModelId,
    threshold: threatThreshold,
  });
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
