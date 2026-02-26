import 'dotenv/config';
import express from 'express';
import session from 'express-session';
import { createServer as createViteServer } from 'vite';
import { TelegramClient } from 'telegram';
import { StringSession } from 'telegram/sessions/index.js';
import { NewMessage } from 'telegram/events/index.js';
import cors from 'cors';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { env as hfEnv, pipeline } from '@huggingface/transformers';

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
const MODEL_CACHE_DIR = path.resolve(__dirname, '.cache', 'models');
const RUNTIME_DIR = path.resolve(__dirname, '.runtime');
const SETTINGS_FILE = path.join(RUNTIME_DIR, 'admin-settings.json');
type UserRole = 'admin' | 'viewer';
type UserStore = Record<string, { password: string; role: UserRole }>;
type PersistedAppSettings = {
  apiId: string;
  apiHash: string;
  botToken: string;
  sessionName: string;
  targetChats: string[];
  proxyEnabled: boolean;
  proxyType: string;
  proxyHost: string;
  proxyPort: string;
  proxyUser: string;
  proxyPass: string;
  downloadMedia: boolean;
  mediaTypes: {
    photo: boolean;
    video: boolean;
    document: boolean;
    audio: boolean;
  };
  keywords: string[];
  mlModel: string;
  threatThreshold: number; // 1..99
};
type TelegramBotCredentials = {
  apiId: number;
  apiHash: string;
  botToken: string;
};
type TelegramChatSummary = {
  id: string;
  title: string;
  username: string | null;
  type: 'group' | 'supergroup' | 'channel';
  avatar: string | null;
};
type BotApiResponse<T> = {
  ok: boolean;
  result?: T;
  description?: string;
  error_code?: number;
};
type BotApiChat = {
  id: number | string;
  type?: string;
  title?: string;
  username?: string;
  photo?: {
    small_file_id?: string;
    big_file_id?: string;
  };
};

fs.mkdirSync(MODEL_CACHE_DIR, { recursive: true });
fs.mkdirSync(RUNTIME_DIR, { recursive: true });
hfEnv.cacheDir = MODEL_CACHE_DIR;
hfEnv.allowLocalModels = true;

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
type ThreatType = 'safe' | 'toxicity' | 'threat' | 'scam';
type RiskCategory = Exclude<ThreatType, 'safe'>;
type RiskScores = Record<RiskCategory, number>;
type LabelScore = { label: string; score: number };
type LocalOnnxOptions = {
  model_file_name?: string;
  subfolder?: string;
  dtype?: 'fp32' | 'fp16' | 'q8';
};

type ThreatModelConfig = {
  id: string;
  name: string;
  description: string;
  repo: string;
  inferenceOptions?: LocalOnnxOptions;
  labelHints: {
    toxicity: string[];
    threat: string[];
    scam: string[];
  };
};

const MODEL_CONFIGS: Record<string, ThreatModelConfig> = {
  'local/rubert-tiny-balanced': {
    id: 'local/rubert-tiny-balanced',
    name: 'RuBERT Tiny ONNX (Balanced)',
    description: 'Default local Russian toxicity model. Good quality and stable confidence.',
    repo: 'aafoninsky/rubert-tiny-toxicity-onnx',
    inferenceOptions: {
      dtype: 'fp32',
    },
    labelHints: {
      toxicity: ['toxic', 'toxicity', 'insult', 'obscene', 'abuse', 'offensive'],
      threat: ['threat', 'dangerous', 'violence', 'kill'],
      scam: ['fraud', 'scam', 'phishing', 'spam'],
    },
  },
  'local/rubert-tiny-quantized': {
    id: 'local/rubert-tiny-quantized',
    name: 'RuBERT Tiny ONNX (Quantized)',
    description: 'Lower RAM profile using quantized ONNX weights. Best for small VPS.',
    repo: 'aafoninsky/rubert-tiny-toxicity-onnx',
    inferenceOptions: {
      model_file_name: 'model_quantized',
      subfolder: 'onnx',
      dtype: 'fp32',
    },
    labelHints: {
      toxicity: ['toxic', 'toxicity', 'insult', 'obscene', 'abuse', 'offensive'],
      threat: ['threat', 'dangerous', 'violence', 'kill'],
      scam: ['fraud', 'scam', 'phishing', 'spam'],
    },
  },
  'local/rubert-tiny-fp16': {
    id: 'local/rubert-tiny-fp16',
    name: 'RuBERT Tiny ONNX (FP16 Optimized)',
    description: 'Alternative ONNX export optimized for throughput on CPU.',
    repo: 'morzecrew/rubert-tiny-toxicity-onnx-optimized-fp16',
    inferenceOptions: {
      model_file_name: 'optimized_fp16',
      subfolder: '',
      dtype: 'fp32',
    },
    labelHints: {
      toxicity: ['toxic', 'toxicity', 'insult', 'obscene', 'abuse', 'offensive'],
      threat: ['threat', 'dangerous', 'violence', 'kill'],
      scam: ['fraud', 'scam', 'phishing', 'spam'],
    },
  },
};
const DEFAULT_MODEL_ID = 'local/rubert-tiny-balanced';
const DEFAULT_PERSISTED_SETTINGS: PersistedAppSettings = {
  apiId: '',
  apiHash: '',
  botToken: '',
  sessionName: 'sentinel_session',
  targetChats: ['-1003803680927'],
  proxyEnabled: false,
  proxyType: 'SOCKS5',
  proxyHost: '127.0.0.1',
  proxyPort: '1080',
  proxyUser: '',
  proxyPass: '',
  downloadMedia: false,
  mediaTypes: {
    photo: true,
    video: false,
    document: false,
    audio: false,
  },
  keywords: ['crypto', 'hack', 'buy', 'sell', 'leak'],
  mlModel: DEFAULT_MODEL_ID,
  threatThreshold: 75,
};
type TextClassifier = (text: string, options?: { top_k?: number }) => Promise<unknown>;
const classifierCache = new Map<string, Promise<TextClassifier>>();
const SAFE_LABEL_HINTS = ['non-toxic', 'not-toxic', 'safe', 'neutral', 'label-0'];
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
const CRITICAL_PATTERNS: Record<RiskCategory, Array<{ pattern: RegExp; score: number }>> = {
  toxicity: [
    { pattern: /\b(чмо|пидор|пидр|мразь|сука|шлюха)\b/i, score: 0.88 },
  ],
  threat: [
    { pattern: /\b(убью|убить|взорву|зарежу|расстреляю|смерть)\b/i, score: 0.92 },
    { pattern: /\b(наркот(ик|а|ики|ики?)|наркота|закладк|кладмен|меф|амф|кокс|героин|гашиш|марихуан|спайс|соль|mdma|экстази|weed)\b/i, score: 0.9 },
  ],
  scam: [
    { pattern: /\b(скам|scam|мошенн|фишинг|обман|развод)\b/i, score: 0.92 },
    { pattern: /\b(seed phrase|сид фраз|кошел[её]к|перев(е|ео)д(и|ите)?|cvv|p2p|арбитраж|гарантированн(ый|ая)? доход|быстрый доход)\b/i, score: 0.88 },
  ],
};

function toStringValue(value: unknown, fallback: string): string {
  return typeof value === 'string' ? value : fallback;
}

function toBooleanValue(value: unknown, fallback: boolean): boolean {
  return typeof value === 'boolean' ? value : fallback;
}

function toStringArray(value: unknown, fallback: string[]): string[] {
  if (!Array.isArray(value)) {
    return fallback;
  }
  const result = value
    .filter((item) => typeof item === 'string')
    .map((item) => item.trim())
    .filter((item) => item.length > 0);
  return result.length > 0 ? result : fallback;
}

function normalizeThresholdPercent(value: unknown, fallback: number): number {
  const fallbackSafe = Math.min(99, Math.max(1, Math.round(fallback)));
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return fallbackSafe;
  }
  const normalized = value > 1 ? value / 100 : value;
  return Math.min(99, Math.max(1, Math.round(normalized * 100)));
}

function sanitizePersistedSettings(
  input: unknown,
  fallback: PersistedAppSettings = DEFAULT_PERSISTED_SETTINGS
): PersistedAppSettings {
  const raw = typeof input === 'object' && input !== null ? (input as Record<string, unknown>) : {};
  const mediaTypesRaw =
    typeof raw.mediaTypes === 'object' && raw.mediaTypes !== null
      ? (raw.mediaTypes as Record<string, unknown>)
      : {};

  const mlModelCandidate = toStringValue(raw.mlModel, fallback.mlModel);
  const mlModel = MODEL_CONFIGS[mlModelCandidate] ? mlModelCandidate : fallback.mlModel;

  return {
    apiId: toStringValue(raw.apiId, fallback.apiId),
    apiHash: toStringValue(raw.apiHash, fallback.apiHash),
    botToken: toStringValue(raw.botToken, fallback.botToken),
    sessionName: toStringValue(raw.sessionName, fallback.sessionName),
    targetChats: toStringArray(raw.targetChats, fallback.targetChats),
    proxyEnabled: toBooleanValue(raw.proxyEnabled, fallback.proxyEnabled),
    proxyType: toStringValue(raw.proxyType, fallback.proxyType),
    proxyHost: toStringValue(raw.proxyHost, fallback.proxyHost),
    proxyPort: toStringValue(raw.proxyPort, fallback.proxyPort),
    proxyUser: toStringValue(raw.proxyUser, fallback.proxyUser),
    proxyPass: toStringValue(raw.proxyPass, fallback.proxyPass),
    downloadMedia: toBooleanValue(raw.downloadMedia, fallback.downloadMedia),
    mediaTypes: {
      photo: toBooleanValue(mediaTypesRaw.photo, fallback.mediaTypes.photo),
      video: toBooleanValue(mediaTypesRaw.video, fallback.mediaTypes.video),
      document: toBooleanValue(mediaTypesRaw.document, fallback.mediaTypes.document),
      audio: toBooleanValue(mediaTypesRaw.audio, fallback.mediaTypes.audio),
    },
    keywords: toStringArray(raw.keywords, fallback.keywords),
    mlModel,
    threatThreshold: normalizeThresholdPercent(raw.threatThreshold, fallback.threatThreshold),
  };
}

function loadPersistedSettings(): PersistedAppSettings {
  if (!fs.existsSync(SETTINGS_FILE)) {
    return { ...DEFAULT_PERSISTED_SETTINGS };
  }

  try {
    const raw = fs.readFileSync(SETTINGS_FILE, 'utf8');
    const parsed = JSON.parse(raw);
    return sanitizePersistedSettings(parsed, DEFAULT_PERSISTED_SETTINGS);
  } catch (error) {
    console.warn(`Failed to load persisted settings: ${(error as Error).message}`);
    return { ...DEFAULT_PERSISTED_SETTINGS };
  }
}

function savePersistedSettings(settings: PersistedAppSettings): void {
  fs.mkdirSync(RUNTIME_DIR, { recursive: true });
  fs.writeFileSync(SETTINGS_FILE, JSON.stringify(settings, null, 2), { encoding: 'utf8', mode: 0o600 });
}

function parsePositiveInteger(value: string): number | null {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    return null;
  }
  return parsed;
}

function resolveTelegramCredentials(source: unknown): {
  apiId: string;
  apiHash: string;
  botToken: string;
} {
  const raw = typeof source === 'object' && source !== null ? (source as Record<string, unknown>) : {};
  return {
    apiId: toStringValue(raw.apiId, persistedSettings.apiId).trim(),
    apiHash: toStringValue(raw.apiHash, persistedSettings.apiHash).trim(),
    botToken: toStringValue(raw.botToken, persistedSettings.botToken).trim(),
  };
}

function resolveChatType(dialog: any): TelegramChatSummary['type'] | null {
  if (!dialog) return null;
  if (dialog.isGroup) {
    return 'group';
  }
  if (!dialog.isChannel) {
    return null;
  }

  const entity = dialog.entity as Record<string, unknown> | undefined;
  if (entity?.megagroup === true) {
    return 'supergroup';
  }
  return 'channel';
}

function resolveChatTitle(dialog: any): string {
  const title = typeof dialog?.title === 'string' && dialog.title.trim().length > 0
    ? dialog.title.trim()
    : typeof dialog?.name === 'string' && dialog.name.trim().length > 0
      ? dialog.name.trim()
      : 'Unknown Chat';
  return title;
}

function resolveChatUsername(dialog: any): string | null {
  const entity = dialog?.entity as Record<string, unknown> | undefined;
  if (!entity) return null;
  const username = entity.username;
  if (typeof username === 'string' && username.trim().length > 0) {
    return username.trim();
  }
  return null;
}

async function resolveChatAvatar(clientRef: TelegramClient, entity: unknown): Promise<string | null> {
  try {
    const profilePhoto = await clientRef.downloadProfilePhoto(entity as any, { isBig: false });
    if (Buffer.isBuffer(profilePhoto) && profilePhoto.length > 0) {
      return `data:image/jpeg;base64,${profilePhoto.toString('base64')}`;
    }
    if (typeof profilePhoto === 'string' && fs.existsSync(profilePhoto)) {
      const bytes = fs.readFileSync(profilePhoto);
      try {
        fs.unlinkSync(profilePhoto);
      } catch {
        // ignore cleanup errors
      }
      if (bytes.length > 0) {
        return `data:image/jpeg;base64,${bytes.toString('base64')}`;
      }
    }
  } catch (error) {
    console.warn(`Failed to fetch chat avatar: ${(error as Error).message}`);
  }
  return null;
}

async function callTelegramBotApi<T>(
  botToken: string,
  method: string,
  payload?: Record<string, unknown>
): Promise<T> {
  const url = `https://api.telegram.org/bot${botToken}/${method}`;
  const response = await fetch(url, {
    method: payload ? 'POST' : 'GET',
    headers: payload ? { 'Content-Type': 'application/json' } : undefined,
    body: payload ? JSON.stringify(payload) : undefined,
  });

  const data = (await response.json()) as BotApiResponse<T>;
  if (!response.ok || !data.ok || data.result === undefined) {
    const description = data.description ?? `Telegram Bot API ${method} failed`;
    throw new Error(description);
  }

  return data.result;
}

function toTelegramChatType(value: unknown): TelegramChatSummary['type'] {
  if (value === 'channel') return 'channel';
  if (value === 'supergroup') return 'supergroup';
  return 'group';
}

function inferChatTypeFromId(chatId: string): TelegramChatSummary['type'] {
  if (chatId.startsWith('-100')) {
    return 'supergroup';
  }
  return 'group';
}

async function resolveBotApiChatAvatar(botToken: string, chat: BotApiChat): Promise<string | null> {
  const fileId = chat.photo?.small_file_id ?? chat.photo?.big_file_id;
  if (!fileId) {
    return null;
  }

  try {
    const fileInfo = await callTelegramBotApi<{ file_path?: string }>(botToken, 'getFile', { file_id: fileId });
    if (!fileInfo.file_path) {
      return null;
    }

    const fileResponse = await fetch(`https://api.telegram.org/file/bot${botToken}/${fileInfo.file_path}`);
    if (!fileResponse.ok) {
      return null;
    }

    const bytes = Buffer.from(await fileResponse.arrayBuffer());
    if (bytes.length === 0) {
      return null;
    }

    return `data:image/jpeg;base64,${bytes.toString('base64')}`;
  } catch {
    return null;
  }
}

function extractChatsFromBotUpdates(updates: Array<Record<string, unknown>>): BotApiChat[] {
  const result: BotApiChat[] = [];
  const seen = new Set<string>();

  const pushChat = (value: unknown) => {
    if (typeof value !== 'object' || value === null) return;
    const chat = value as BotApiChat;
    const id = String(chat.id ?? '');
    if (!id || seen.has(id)) return;
    seen.add(id);
    result.push(chat);
  };

  for (const update of updates) {
    const candidate = update as Record<string, any>;
    pushChat(candidate.message?.chat);
    pushChat(candidate.edited_message?.chat);
    pushChat(candidate.channel_post?.chat);
    pushChat(candidate.edited_channel_post?.chat);
    pushChat(candidate.my_chat_member?.chat);
    pushChat(candidate.chat_member?.chat);
  }

  return result;
}

async function collectTelegramChatsViaBotApi(
  botToken: string,
  fallbackTargetChats: string[]
): Promise<TelegramChatSummary[]> {
  const updates = await callTelegramBotApi<Array<Record<string, unknown>>>(botToken, 'getUpdates', {
    limit: 100,
    timeout: 0,
    allowed_updates: [
      'message',
      'edited_message',
      'channel_post',
      'edited_channel_post',
      'my_chat_member',
      'chat_member',
    ],
  });

  const chatsById = new Map<string, TelegramChatSummary>();
  const updateChats = extractChatsFromBotUpdates(updates);

  for (const updateChat of updateChats.slice(0, 80)) {
    const chatId = String(updateChat.id ?? '').trim();
    if (!chatId) continue;

    let detailedChat: BotApiChat = updateChat;
    try {
      detailedChat = await callTelegramBotApi<BotApiChat>(botToken, 'getChat', { chat_id: chatId });
    } catch {
      // keep update payload if getChat is unavailable
    }

    chatsById.set(chatId, {
      id: chatId,
      title:
        (typeof detailedChat.title === 'string' && detailedChat.title.trim()) ||
        (typeof detailedChat.username === 'string' && `@${detailedChat.username.trim()}`) ||
        `Chat ${chatId}`,
      username:
        typeof detailedChat.username === 'string' && detailedChat.username.trim().length > 0
          ? detailedChat.username.trim()
          : null,
      type: toTelegramChatType(detailedChat.type),
      avatar: await resolveBotApiChatAvatar(botToken, detailedChat),
    });
  }

  for (const chatIdRaw of fallbackTargetChats) {
    const chatId = String(chatIdRaw).trim();
    if (!chatId || chatsById.has(chatId)) continue;
    chatsById.set(chatId, {
      id: chatId,
      title: `Chat ${chatId}`,
      username: null,
      type: inferChatTypeFromId(chatId),
      avatar: null,
    });
  }

  return Array.from(chatsById.values()).sort((left, right) =>
    left.title.localeCompare(right.title, 'ru', { sensitivity: 'base' })
  );
}

function isDialogsForbiddenForBot(error: unknown): boolean {
  const message = (error as Error)?.message ?? '';
  return message.includes('BOT_METHOD_INVALID') || message.includes('messages.GetDialogs');
}

async function collectTelegramChats(clientRef: TelegramClient): Promise<TelegramChatSummary[]> {
  const dialogs = await clientRef.getDialogs({ limit: 200 });
  const chats: TelegramChatSummary[] = [];
  const knownChatIds = new Set<string>();

  for (const dialog of dialogs) {
    const chatType = resolveChatType(dialog);
    if (!chatType) {
      continue;
    }

    const peer = dialog.entity ?? dialog.inputEntity;
    if (!peer) {
      continue;
    }

    let chatId = '';
    try {
      chatId = await clientRef.getPeerId(peer);
    } catch {
      continue;
    }
    if (!chatId || knownChatIds.has(chatId)) {
      continue;
    }

    knownChatIds.add(chatId);
    chats.push({
      id: chatId,
      title: resolveChatTitle(dialog),
      username: resolveChatUsername(dialog),
      type: chatType,
      avatar: dialog.entity ? await resolveChatAvatar(clientRef, dialog.entity) : null,
    });

    if (chats.length >= 120) {
      break;
    }
  }

  chats.sort((left, right) => left.title.localeCompare(right.title, 'ru', { sensitivity: 'base' }));
  return chats;
}

async function runWithBotClient<T>(
  credentials: TelegramBotCredentials,
  reuseRunningClient: boolean,
  action: (clientRef: TelegramClient) => Promise<T>
): Promise<T> {
  if (reuseRunningClient && client && isRunning) {
    return action(client);
  }

  const tempSession = new StringSession('');
  const tempClient = new TelegramClient(tempSession, credentials.apiId, credentials.apiHash, {
    connectionRetries: 3,
  });

  await tempClient.start({
    botAuthToken: credentials.botToken,
  });

  try {
    return await action(tempClient);
  } finally {
    await tempClient.disconnect().catch(() => undefined);
  }
}

function applyPersistedSettings(settings: PersistedAppSettings): void {
  selectedModelId = settings.mlModel;
  threatThreshold = settings.threatThreshold / 100;
  targetChats = [...settings.targetChats];
}

let persistedSettings = loadPersistedSettings();
let selectedModelId = persistedSettings.mlModel;
let threatThreshold = persistedSettings.threatThreshold / 100;
let targetChats: string[] = [...persistedSettings.targetChats];
applyPersistedSettings(persistedSettings);
if (!fs.existsSync(SETTINGS_FILE)) {
  savePersistedSettings(persistedSettings);
}

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

app.get('/api/settings', isAdmin, (_req, res) => {
  res.json(persistedSettings);
});

app.post('/api/settings', isAdmin, (req, res) => {
  const merged = sanitizePersistedSettings(req.body, persistedSettings);
  persistedSettings = merged;
  applyPersistedSettings(merged);
  savePersistedSettings(merged);
  res.json({ status: 'saved', settings: merged });
});

app.post('/api/telegram/chats', isAdmin, async (req, res) => {
  const creds = resolveTelegramCredentials(req.body);
  if (!creds.botToken) {
    return res.status(400).json({ error: 'Bot Token is required' });
  }

  const parsedApiId = parsePositiveInteger(creds.apiId);
  const hasMtprotoCreds = !!parsedApiId && !!creds.apiHash;

  const reuseRunningClient =
    hasMtprotoCreds &&
    !!client &&
    isRunning &&
    creds.apiId === persistedSettings.apiId &&
    creds.apiHash === persistedSettings.apiHash &&
    creds.botToken === persistedSettings.botToken;

  try {
    let chats: TelegramChatSummary[] = [];

    if (hasMtprotoCreds) {
      try {
        chats = await runWithBotClient(
          {
            apiId: parsedApiId as number,
            apiHash: creds.apiHash,
            botToken: creds.botToken,
          },
          reuseRunningClient,
          collectTelegramChats
        );
      } catch (error) {
        if (!isDialogsForbiddenForBot(error)) {
          throw error;
        }
        chats = await collectTelegramChatsViaBotApi(creds.botToken, persistedSettings.targetChats);
      }
    } else {
      chats = await collectTelegramChatsViaBotApi(creds.botToken, persistedSettings.targetChats);
    }

    res.json({ chats });
  } catch (error) {
    res.status(500).json({ error: (error as Error).message });
  }
});

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

function normalizeLabelKey(value: string): string {
  return value.toLowerCase().replace(/[_\s]+/g, '-').trim();
}

function isSafeLabel(label: string): boolean {
  const normalized = normalizeLabelKey(label);
  if (SAFE_LABEL_HINTS.includes(normalized)) return true;
  if (normalized.startsWith('non-toxic')) return true;
  if (normalized.startsWith('not-toxic')) return true;
  return false;
}

function matchesAnyHint(label: string, hints: string[]): boolean {
  const normalizedLabel = normalizeLabelKey(label);
  return hints.some((hint) => normalizedLabel.includes(normalizeLabelKey(hint)));
}

function extractModelScores(modelId: string, labels: LabelScore[]): RiskScores {
  const scores = emptyRiskScores();
  const config = MODEL_CONFIGS[modelId] ?? MODEL_CONFIGS[DEFAULT_MODEL_ID];

  for (const { label: rawLabel, score } of labels) {
    const label = normalizeLabelKey(rawLabel);

    if (isSafeLabel(label)) {
      continue;
    }

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

async function getClassifier(modelId: string): Promise<TextClassifier> {
  const config = MODEL_CONFIGS[modelId] ?? MODEL_CONFIGS[DEFAULT_MODEL_ID];
  let classifierPromise = classifierCache.get(config.id);

  if (!classifierPromise) {
    classifierPromise = (async () => {
      console.log(`Loading local ONNX model: ${config.name} (${config.repo})`);
      const classifier = await pipeline('text-classification', config.repo, config.inferenceOptions ?? {});
      return classifier as TextClassifier;
    })();
    classifierCache.set(config.id, classifierPromise);
  }

  return classifierPromise;
}

function heuristicScores(text: string): RiskScores {
  const scores = emptyRiskScores();

  (Object.keys(HEURISTIC_PATTERNS) as RiskCategory[]).forEach((category) => {
    const hits = HEURISTIC_PATTERNS[category].reduce((sum, pattern) => sum + (pattern.test(text) ? 1 : 0), 0);
    scores[category] = clamp01(Math.min(0.92, hits * 0.28));
  });

  (Object.keys(CRITICAL_PATTERNS) as RiskCategory[]).forEach((category) => {
    for (const rule of CRITICAL_PATTERNS[category]) {
      if (rule.pattern.test(text)) {
        scores[category] = Math.max(scores[category], rule.score);
      }
    }
  });

  if (/https?:\/\//i.test(text) && /(перевод|оплат|кошел|card|wallet|крипт|btc|usdt|биржа|p2p)/i.test(text)) {
    scores.scam = Math.max(scores.scam, 0.84);
  }

  return scores;
}

async function requestModelScores(modelId: string, text: string): Promise<RiskScores> {
  const classifier = await getClassifier(modelId);
  const payload = await classifier(text.slice(0, 1000), { top_k: 10 });
  const labels = normalizeLabelScores(payload);
  return extractModelScores(modelId, labels);
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
  const resolvedApiId = toStringValue(apiId, persistedSettings.apiId).trim();
  const resolvedApiHash = toStringValue(apiHash, persistedSettings.apiHash).trim();
  const resolvedBotToken = toStringValue(botToken, persistedSettings.botToken).trim();
  const resolvedChats = Array.isArray(chats)
    ? toStringArray(chats, persistedSettings.targetChats)
    : persistedSettings.targetChats;
  const resolvedModel = typeof model === 'string' && MODEL_CONFIGS[model] ? model : persistedSettings.mlModel;
  const resolvedThreshold =
    requestedThreshold === undefined
      ? persistedSettings.threatThreshold / 100
      : normalizeThreshold(requestedThreshold);

  if (!resolvedApiId || !resolvedApiHash || !resolvedBotToken) {
    return res.status(400).json({ error: 'API ID, API Hash, and Bot Token are required' });
  }

  persistedSettings = sanitizePersistedSettings(
    {
      ...persistedSettings,
      apiId: resolvedApiId,
      apiHash: resolvedApiHash,
      botToken: resolvedBotToken,
      targetChats: resolvedChats,
      mlModel: resolvedModel,
      threatThreshold: Math.round(resolvedThreshold * 100),
    },
    persistedSettings
  );
  applyPersistedSettings(persistedSettings);
  savePersistedSettings(persistedSettings);
  
  try {
    await getClassifier(selectedModelId);

    const stringSession = new StringSession('');
    client = new TelegramClient(stringSession, Number(resolvedApiId), resolvedApiHash, {
      connectionRetries: 5,
    });
    
    await client.start({
      botAuthToken: resolvedBotToken,
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
      inferenceBackend: 'local-onnx',
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
