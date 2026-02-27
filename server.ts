import 'dotenv/config';
import express from 'express';
import session from 'express-session';
import { createServer as createViteServer } from 'vite';
import { Api, TelegramClient } from 'telegram';
import { StringSession } from 'telegram/sessions/index.js';
import { NewMessage } from 'telegram/events/index.js';
import cors from 'cors';
import fs from 'fs';
import path from 'path';
import { randomUUID } from 'crypto';
import { fileURLToPath } from 'url';
import { env as hfEnv, pipeline } from '@huggingface/transformers';
import Database from 'better-sqlite3';

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
const MESSAGES_DB_FILE = path.join(RUNTIME_DIR, 'messages.sqlite3');
type UserRole = 'admin' | 'viewer';
type UserStore = Record<string, { password: string; role: UserRole }>;
type TelegramAuthMode = 'bot' | 'user';
type EngineCategoryThresholds = {
  toxicity: number;
  threat: number;
  scam: number;
  recruitment: number;
  drugs: number;
  terrorism: number;
};
type PersistedAppSettings = {
  apiId: string;
  apiHash: string;
  authMode: TelegramAuthMode;
  botToken: string;
  sessionString: string;
  sessionName: string;
  userAuthAllMessages: boolean;
  botTargetChats: string[];
  userTargetChats: string[];
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
  scamTriggers: string[];
  drugTriggers: string[];
  recruitmentTriggers: string[];
  terrorismTriggers: string[];
  threatTriggers: string[];
  toxicityTriggers: string[];
  mlModel: string;
  threatThreshold: number; // 1..99
  categoryThresholds: EngineCategoryThresholds;
  enableHeuristics: boolean;
  enableCriticalPatterns: boolean;
  modelWeight: number; // 0..100
  heuristicWeight: number; // 0..100
  modelTopK: number; // 1..30
  maxAnalysisChars: number; // 200..4000
  urlScamBoost: number; // 0..100
  keywordHitBoost: number; // 0..100
  criticalHitFloor: number; // 0..100
};
type TelegramUserCredentials = {
  apiId: number;
  apiHash: string;
  sessionString: string;
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
type PendingSessionAuth = {
  id: string;
  client: TelegramClient;
  stringSession: StringSession;
  apiId: number;
  apiHash: string;
  phoneNumber: string;
  phoneCodeHash: string;
  createdAt: number;
};
type RateLimitEntry = {
  windowStart: number;
  count: number;
  blockedUntil: number;
};
type RateLimitConfig = {
  windowMs: number;
  max: number;
  cooldownMs: number;
  error: string;
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
const SESSION_AUTH_TTL_MS = 15 * 60 * 1000;
const pendingSessionAuth = new Map<string, PendingSessionAuth>();
const rateLimitStore = new Map<string, RateLimitEntry>();

let client: TelegramClient | null = null;
let isRunning = false;
const MAX_RECENT_MESSAGES = 300;
type ThreatType =
  | 'safe'
  | 'toxicity'
  | 'threat'
  | 'scam'
  | 'recruitment'
  | 'drugs'
  | 'terrorism';
type RiskCategory = Exclude<ThreatType, 'safe'>;
type RiskScores = Record<RiskCategory, number>;
const RISK_CATEGORIES: RiskCategory[] = [
  'toxicity',
  'threat',
  'scam',
  'recruitment',
  'drugs',
  'terrorism',
];
type AnalyzeThreatResult = {
  type: ThreatType;
  score: number;
  scores: RiskScores;
  heuristicScores: RiskScores;
  modelScores: RiskScores;
  thresholds: RiskScores;
};
type StoredThreatStats = Record<ThreatType, number>;
type StoredMessageRow = {
  id: number;
  telegramMessageId: number | null;
  telegramChatId: string | null;
  messageTs: number;
  chat: string;
  sender: string;
  text: string;
  type: ThreatType;
  score: number;
};
type StoredMessageInput = {
  telegramMessageId: number | null;
  telegramChatId: string | null;
  messageTs: number;
  chat: string;
  sender: string;
  text: string;
  type: ThreatType;
  score: number;
};
type LabelScore = { label: string; score: number };
type LocalOnnxOptions = {
  model_file_name?: string;
  subfolder?: string;
  dtype?: 'fp32' | 'fp16' | 'q8';
};
type ModelTask = 'text-classification' | 'zero-shot-classification';
type ZeroShotConfig = {
  candidateLabels: Record<RiskCategory, string>;
  hypothesisTemplate?: string;
  multiLabel?: boolean;
};

type ThreatModelConfig = {
  id: string;
  name: string;
  description: string;
  repo: string;
  task: ModelTask;
  inferenceOptions?: LocalOnnxOptions;
  zeroShot?: ZeroShotConfig;
  labelHints: {
    toxicity: string[];
    threat: string[];
    scam: string[];
    recruitment: string[];
    drugs: string[];
    terrorism: string[];
  };
};

const THREAT_TYPES: ThreatType[] = [
  'safe',
  'toxicity',
  'threat',
  'scam',
  'recruitment',
  'drugs',
  'terrorism',
];

const messageDb = new Database(MESSAGES_DB_FILE);
messageDb.pragma('journal_mode = WAL');
messageDb.pragma('synchronous = NORMAL');
messageDb.exec(`
  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    telegram_message_id INTEGER,
    telegram_chat_id TEXT,
    message_ts INTEGER NOT NULL,
    received_ts INTEGER NOT NULL,
    chat TEXT NOT NULL,
    sender TEXT NOT NULL,
    text TEXT NOT NULL,
    type TEXT NOT NULL,
    score REAL NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_messages_received_ts ON messages(received_ts DESC);
  CREATE INDEX IF NOT EXISTS idx_messages_type ON messages(type);
`);

const insertMessageStmt = messageDb.prepare(`
  INSERT INTO messages (
    telegram_message_id,
    telegram_chat_id,
    message_ts,
    received_ts,
    chat,
    sender,
    text,
    type,
    score
  ) VALUES (
    @telegramMessageId,
    @telegramChatId,
    @messageTs,
    @receivedTs,
    @chat,
    @sender,
    @text,
    @type,
    @score
  )
`);

const selectRecentMessagesStmt = messageDb.prepare(`
  SELECT
    id,
    telegram_message_id AS telegramMessageId,
    telegram_chat_id AS telegramChatId,
    message_ts AS messageTs,
    chat,
    sender,
    text,
    type,
    score
  FROM messages
  ORDER BY received_ts DESC
  LIMIT ?
`);

const selectThreatStatsStmt = messageDb.prepare(`
  SELECT type, COUNT(*) AS total
  FROM messages
  GROUP BY type
`);

function storeMessage(entry: StoredMessageInput): void {
  try {
    insertMessageStmt.run({
      telegramMessageId: entry.telegramMessageId,
      telegramChatId: entry.telegramChatId,
      messageTs: Number.isFinite(entry.messageTs) ? Math.max(0, Math.floor(entry.messageTs)) : Math.floor(Date.now() / 1000),
      receivedTs: Date.now(),
      chat: entry.chat,
      sender: entry.sender,
      text: entry.text,
      type: entry.type,
      score: clamp01(entry.score),
    });
  } catch (error) {
    console.error(`Failed to store message in DB: ${(error as Error).message}`);
  }
}

function readRecentMessages(limit = MAX_RECENT_MESSAGES): Array<{
  id: number;
  time: string;
  chat: string;
  sender: string;
  text: string;
  type: ThreatType;
  score: number;
}> {
  const safeLimit = Math.min(1000, Math.max(1, Math.floor(limit)));
  const rows = selectRecentMessagesStmt.all(safeLimit) as StoredMessageRow[];
  return rows.map((row) => {
    const messageTs = Number.isFinite(row.messageTs) ? row.messageTs : Math.floor(Date.now() / 1000);
    const messageType = THREAT_TYPES.includes(row.type as ThreatType) ? (row.type as ThreatType) : 'safe';
    return {
      id: row.id,
      time: new Date(messageTs * 1000).toLocaleTimeString(),
      chat: row.chat,
      sender: row.sender,
      text: row.text,
      type: messageType,
      score: clamp01(row.score),
    };
  });
}

function readThreatStats(): StoredThreatStats {
  const base: StoredThreatStats = {
    safe: 0,
    toxicity: 0,
    threat: 0,
    scam: 0,
    recruitment: 0,
    drugs: 0,
    terrorism: 0,
  };
  const rows = selectThreatStatsStmt.all() as Array<{ type: string; total: number }>;
  for (const row of rows) {
    if (THREAT_TYPES.includes(row.type as ThreatType)) {
      base[row.type as ThreatType] = Number(row.total) || 0;
    }
  }
  return base;
}

const MODEL_CONFIGS: Record<string, ThreatModelConfig> = {
  'local/rubert-tiny-balanced': {
    id: 'local/rubert-tiny-balanced',
    name: 'RuBERT Tiny ONNX (Balanced)',
    description: 'Default local Russian toxicity model. Good quality and stable confidence.',
    repo: 'aafoninsky/rubert-tiny-toxicity-onnx',
    task: 'text-classification',
    inferenceOptions: {
      dtype: 'fp32',
    },
    labelHints: {
      toxicity: ['toxic', 'toxicity', 'insult', 'obscene', 'abuse', 'offensive'],
      threat: ['threat', 'dangerous', 'violence', 'kill'],
      scam: ['fraud', 'scam', 'phishing', 'spam'],
      recruitment: ['recruitment', 'radicalization', 'extremism'],
      drugs: ['drugs', 'narcotics', 'substance'],
      terrorism: ['terrorism', 'terror', 'extremist'],
    },
  },
  'local/rubert-tiny-quantized': {
    id: 'local/rubert-tiny-quantized',
    name: 'RuBERT Tiny ONNX (Quantized)',
    description: 'Lower RAM profile using quantized ONNX weights. Best for small VPS.',
    repo: 'aafoninsky/rubert-tiny-toxicity-onnx',
    task: 'text-classification',
    inferenceOptions: {
      model_file_name: 'model_quantized',
      subfolder: 'onnx',
      dtype: 'fp32',
    },
    labelHints: {
      toxicity: ['toxic', 'toxicity', 'insult', 'obscene', 'abuse', 'offensive'],
      threat: ['threat', 'dangerous', 'violence', 'kill'],
      scam: ['fraud', 'scam', 'phishing', 'spam'],
      recruitment: ['recruitment', 'radicalization', 'extremism'],
      drugs: ['drugs', 'narcotics', 'substance'],
      terrorism: ['terrorism', 'terror', 'extremist'],
    },
  },
  'local/rubert-tiny-fp16': {
    id: 'local/rubert-tiny-fp16',
    name: 'RuBERT Tiny ONNX (FP16 Optimized)',
    description: 'Alternative ONNX export optimized for throughput on CPU.',
    repo: 'morzecrew/rubert-tiny-toxicity-onnx-optimized-fp16',
    task: 'text-classification',
    inferenceOptions: {
      model_file_name: 'optimized_fp16',
      subfolder: '',
      dtype: 'fp32',
    },
    labelHints: {
      toxicity: ['toxic', 'toxicity', 'insult', 'obscene', 'abuse', 'offensive'],
      threat: ['threat', 'dangerous', 'violence', 'kill'],
      scam: ['fraud', 'scam', 'phishing', 'spam'],
      recruitment: ['recruitment', 'radicalization', 'extremism'],
      drugs: ['drugs', 'narcotics', 'substance'],
      terrorism: ['terrorism', 'terror', 'extremist'],
    },
  },
  'hf/bert-mini-toxicity-quant': {
    id: 'hf/bert-mini-toxicity-quant',
    name: 'BERT Mini Toxicity (Multilingual Quantized)',
    description: 'Compact multilingual toxicity model with quantized ONNX weights.',
    repo: 'gravitee-io/bert-mini-toxicity',
    task: 'text-classification',
    inferenceOptions: {
      model_file_name: 'model.quant',
      subfolder: '',
      dtype: 'fp32',
    },
    labelHints: {
      toxicity: ['toxic', 'toxicity', 'offensive', 'insult', 'abuse'],
      threat: ['threat', 'dangerous', 'violence', 'kill'],
      scam: ['fraud', 'scam', 'phishing', 'spam'],
      recruitment: ['recruitment', 'radicalization', 'extremism'],
      drugs: ['drugs', 'narcotics', 'substance'],
      terrorism: ['terrorism', 'terror', 'extremist'],
    },
  },
  'hf/bert-small-toxicity-quant': {
    id: 'hf/bert-small-toxicity-quant',
    name: 'BERT Small Toxicity (Multilingual Quantized)',
    description: 'Balanced multilingual toxicity model with stronger quality than mini.',
    repo: 'gravitee-io/bert-small-toxicity',
    task: 'text-classification',
    inferenceOptions: {
      model_file_name: 'model.quant',
      subfolder: '',
      dtype: 'fp32',
    },
    labelHints: {
      toxicity: ['toxic', 'toxicity', 'offensive', 'insult', 'abuse'],
      threat: ['threat', 'dangerous', 'violence', 'kill'],
      scam: ['fraud', 'scam', 'phishing', 'spam'],
      recruitment: ['recruitment', 'radicalization', 'extremism'],
      drugs: ['drugs', 'narcotics', 'substance'],
      terrorism: ['terrorism', 'terror', 'extremist'],
    },
  },
  'hf/distilbert-multilingual-toxicity-quant': {
    id: 'hf/distilbert-multilingual-toxicity-quant',
    name: 'DistilBERT Multilingual Toxicity (Quantized)',
    description: 'Wider multilingual coverage model for toxicity in mixed-language chats.',
    repo: 'gravitee-io/distilbert-multilingual-toxicity-classifier',
    task: 'text-classification',
    inferenceOptions: {
      model_file_name: 'model.quant',
      subfolder: '',
      dtype: 'fp32',
    },
    labelHints: {
      toxicity: ['toxic', 'toxicity', 'offensive', 'insult', 'abuse'],
      threat: ['threat', 'dangerous', 'violence', 'kill'],
      scam: ['fraud', 'scam', 'phishing', 'spam'],
      recruitment: ['recruitment', 'radicalization', 'extremism'],
      drugs: ['drugs', 'narcotics', 'substance'],
      terrorism: ['terrorism', 'terror', 'extremist'],
    },
  },
  'zero-shot/xenova-mdeberta-v3-xnli': {
    id: 'zero-shot/xenova-mdeberta-v3-xnli',
    name: 'mDeBERTa-v3 XNLI (Zero-Shot)',
    description: 'Multilingual zero-shot NLI model for custom moderation categories.',
    repo: 'Xenova/mDeBERTa-v3-base-xnli-multilingual-nli-2mil7',
    task: 'zero-shot-classification',
    inferenceOptions: {
      dtype: 'fp32',
    },
    zeroShot: {
      candidateLabels: {
        toxicity: 'toxic or insulting language',
        threat: 'threats of violence or physical harm',
        scam: 'fraud, scam, phishing, or financial deception',
        recruitment: 'recruitment into illegal or extremist groups',
        drugs: 'drug trafficking, narcotics sale, or stash coordination',
        terrorism: 'terrorism, terror attack planning, or extremist violence',
      },
      hypothesisTemplate: 'This text is about {}.',
      multiLabel: true,
    },
    labelHints: {
      toxicity: ['toxic', 'insulting', 'offensive', 'abusive'],
      threat: ['threat', 'violence', 'harm'],
      scam: ['fraud', 'scam', 'phishing', 'deception'],
      recruitment: ['recruitment', 'illegal group', 'extremist'],
      drugs: ['drug', 'narcotics', 'trafficking', 'stash'],
      terrorism: ['terrorism', 'terror attack', 'extremist violence'],
    },
  },
  'zero-shot/mdeberta-v3-mnli-xnli': {
    id: 'zero-shot/mdeberta-v3-mnli-xnli',
    name: 'mDeBERTa-v3 MNLI/XNLI (Zero-Shot)',
    description: 'General multilingual zero-shot classifier with strong NLI quality.',
    repo: 'MoritzLaurer/mDeBERTa-v3-base-mnli-xnli',
    task: 'zero-shot-classification',
    inferenceOptions: {
      dtype: 'fp32',
    },
    zeroShot: {
      candidateLabels: {
        toxicity: 'toxic or insulting language',
        threat: 'threats of violence or physical harm',
        scam: 'fraud, scam, phishing, or financial deception',
        recruitment: 'recruitment into illegal or extremist groups',
        drugs: 'drug trafficking, narcotics sale, or stash coordination',
        terrorism: 'terrorism, terror attack planning, or extremist violence',
      },
      hypothesisTemplate: 'This text is about {}.',
      multiLabel: true,
    },
    labelHints: {
      toxicity: ['toxic', 'insulting', 'offensive', 'abusive'],
      threat: ['threat', 'violence', 'harm'],
      scam: ['fraud', 'scam', 'phishing', 'deception'],
      recruitment: ['recruitment', 'illegal group', 'extremist'],
      drugs: ['drug', 'narcotics', 'trafficking', 'stash'],
      terrorism: ['terrorism', 'terror attack', 'extremist violence'],
    },
  },
};
const DEFAULT_MODEL_ID = 'local/rubert-tiny-balanced';
const DEFAULT_CATEGORY_THRESHOLDS: EngineCategoryThresholds = {
  toxicity: 72,
  threat: 72,
  scam: 70,
  recruitment: 74,
  drugs: 74,
  terrorism: 76,
};
const DEFAULT_SCAM_TRIGGERS = [
  'скам',
  'мошенник',
  'мошенничество',
  'развод',
  'обман',
  'фишинг',
  'быстрый заработок',
  'гарантированный доход',
  'пассивный доход',
  'раскрутка счета',
  'переведи usdt',
  'seed phrase',
  'сид фраза',
  'wallet connect',
  'подтверди кошелек',
  'арбитраж',
  'предоплата',
  'успей купить',
  'бот для дохода',
  'инвестируй сейчас',
];
const DEFAULT_DRUG_TRIGGERS = [
  'наркотик',
  'наркота',
  'закладка',
  'кладмен',
  'меф',
  'мефедрон',
  'амф',
  'амфетамин',
  'кокс',
  'кокаин',
  'героин',
  'гашиш',
  'марихуана',
  'каннабис',
  'спайс',
  'соль',
  'mdma',
  'экстази',
  'weed',
  'доставка вещества',
];
const DEFAULT_RECRUITMENT_TRIGGERS = [
  'вербовка',
  'ищем людей',
  'закрытая группа',
  'закрытую группу',
  'подпольная ячейка',
  'вступай в движение',
  'нужны участники',
  'радикальные действия',
  'recruit',
  'join the squad',
  'cell recruitment',
  'underground group',
  'closed community',
  'new fighters needed',
  'join movement',
  'tasks for members',
];
const DEFAULT_TERRORISM_TRIGGERS = [
  'теракт',
  'взрывное устройство',
  'массовое нападение',
  'атака на объект',
  'оружие для атаки',
  'terror attack',
  'explosion in public place',
  'attack on target',
  'explosive device',
  'weapon for attack',
  'organize explosion',
  'mass attack',
  'maximum damage',
];
const DEFAULT_THREAT_TRIGGERS = [
  'убью',
  'взорву',
  'зарежу',
  'расстреляю',
  'смерть',
  'теракт',
  'бомба',
  'оружие',
  'нападу',
  'подожгу',
  'угроза',
];
const DEFAULT_TOXICITY_TRIGGERS = [
  'идиот',
  'дебил',
  'тварь',
  'мразь',
  'чмо',
  'сука',
  'урод',
  'пидор',
  'оскорбление',
  'ненавижу',
  'пошел нах',
];
type EngineSelfTestCase = {
  text: string;
  expected: ThreatType;
  scenario: string;
};
type EngineSelfTestPreset =
  | 'all'
  | 'toxicity'
  | 'threat'
  | 'scam'
  | 'recruitment'
  | 'drugs'
  | 'terrorism';
const ENGINE_SELF_TEST_PRESETS: Record<Exclude<EngineSelfTestPreset, 'all'>, EngineSelfTestCase[]> = {
  toxicity: [
    { scenario: 'toxicity', expected: 'toxicity', text: 'Ты идиот и ничтожество, тебя все ненавидят.' },
    { scenario: 'toxicity', expected: 'toxicity', text: 'Какой же ты дебил, закрой рот и исчезни.' },
    { scenario: 'toxicity', expected: 'toxicity', text: 'Ты мразь и урод, с тобой противно общаться.' },
    { scenario: 'toxicity', expected: 'toxicity', text: 'Это тупое чмо, которое ничего не умеет.' },
  ],
  threat: [
    { scenario: 'threat', expected: 'threat', text: 'Я тебя убью, если еще раз напишешь.' },
    { scenario: 'threat', expected: 'threat', text: 'Сегодня взорву ваш офис, это не шутка.' },
    { scenario: 'threat', expected: 'threat', text: 'Зарежу тебя при встрече, готовься.' },
    { scenario: 'threat', expected: 'threat', text: 'Это прямая угроза: ты получишь пулю.' },
  ],
  scam: [
    {
      scenario: 'scam',
      expected: 'scam',
      text: 'Гарантированный доход пятнадцать процентов в день, только сегодня.',
    },
    { scenario: 'scam', expected: 'scam', text: 'Сделай предоплату и получишь доступ к закрытой инвестиции.' },
    { scenario: 'scam', expected: 'scam', text: 'Это не обман, переведи деньги сейчас и завтра удвоим сумму.' },
    { scenario: 'scam', expected: 'scam', text: 'Быстрый заработок без риска, просто переведи оплату менеджеру.' },
  ],
  recruitment: [
    { scenario: 'recruitment', expected: 'recruitment', text: 'Ищем людей в закрытую группу для специальных задач.' },
    {
      scenario: 'recruitment',
      expected: 'recruitment',
      text: 'Нужны новые участники для подпольной ячейки, пиши в личку.',
    },
    { scenario: 'recruitment', expected: 'recruitment', text: 'Вступай в наше движение, обучение и задания дадим сразу.' },
    {
      scenario: 'recruitment',
      expected: 'recruitment',
      text: 'Собираем команду для радикальных действий, нужны проверенные люди.',
    },
  ],
  drugs: [
    { scenario: 'drugs', expected: 'drugs', text: 'Продам мефедрон, есть закладки по городу.' },
    { scenario: 'drugs', expected: 'drugs', text: 'Нужен кладмен на ежедневные развозы вещества.' },
    { scenario: 'drugs', expected: 'drugs', text: 'Есть кокаин и амфетамин, пишите за координатами.' },
    { scenario: 'drugs', expected: 'drugs', text: 'Оплата вперед, потом отправлю адрес закладки.' },
  ],
  terrorism: [
    { scenario: 'terrorism', expected: 'terrorism', text: 'Готовим теракт в людном месте, нужен исполнитель.' },
    { scenario: 'terrorism', expected: 'terrorism', text: 'Нужны люди и оружие для атаки на объект.' },
    { scenario: 'terrorism', expected: 'terrorism', text: 'Соберем взрывное устройство и ударим по толпе.' },
    { scenario: 'terrorism', expected: 'terrorism', text: 'Планируем массовое нападение, цель - максимальный ущерб.' },
  ],
};
const ENGINE_SELF_TEST_MESSAGES: EngineSelfTestCase[] = Object.values(ENGINE_SELF_TEST_PRESETS).flat();
const DEFAULT_PERSISTED_SETTINGS: PersistedAppSettings = {
  apiId: '',
  apiHash: '',
  authMode: 'bot',
  botToken: '',
  sessionString: '',
  sessionName: 'sentinel_session',
  userAuthAllMessages: false,
  botTargetChats: ['-1003803680927'],
  userTargetChats: ['-1003803680927'],
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
  keywords: ['crypto', 'invest', 'wallet', 'usdt', 'btc', 'перевод', 'кошелек'],
  scamTriggers: [...DEFAULT_SCAM_TRIGGERS],
  drugTriggers: [...DEFAULT_DRUG_TRIGGERS],
  recruitmentTriggers: [...DEFAULT_RECRUITMENT_TRIGGERS],
  terrorismTriggers: [...DEFAULT_TERRORISM_TRIGGERS],
  threatTriggers: [...DEFAULT_THREAT_TRIGGERS],
  toxicityTriggers: [...DEFAULT_TOXICITY_TRIGGERS],
  mlModel: DEFAULT_MODEL_ID,
  threatThreshold: 75,
  categoryThresholds: { ...DEFAULT_CATEGORY_THRESHOLDS },
  enableHeuristics: true,
  enableCriticalPatterns: true,
  modelWeight: 58,
  heuristicWeight: 42,
  modelTopK: 12,
  maxAnalysisChars: 1400,
  urlScamBoost: 24,
  keywordHitBoost: 16,
  criticalHitFloor: 84,
};
type TextClassifier = (...args: unknown[]) => Promise<unknown>;
const classifierCache = new Map<string, Promise<TextClassifier>>();
const SAFE_LABEL_HINTS = ['non-toxic', 'not-toxic', 'safe', 'neutral', 'label-0'];
const HEURISTIC_PATTERNS: Record<RiskCategory, RegExp[]> = {
  toxicity: [
    /\b(idiot|moron|trash|stupid|bitch|fuck|hate you)\b/i,
    /\binsult|abuse|humiliate\b/i,
    /\btoxic\b/i,
    /(идиот|дебил|тварь|мразь|чмо|сука|урод|пидор)/i,
    /(ненавижу|оскорблен|заткнись)/i,
  ],
  threat: [
    /\b(kill|shoot|stab|explode|bomb|attack|weapon)\b/i,
    /\bthreat|violence|harm\b/i,
    /\btarget\b/i,
    /(убью|взорву|зарежу|расстреляю|угроз|бомб|оружие)/i,
  ],
  scam: [
    /\b(scam|fraud|phishing|ponzi|prepayment)\b/i,
    /seed phrase/i,
    /\b(private key|passphrase)\b/i,
    /cvv/i,
    /\bwallet connect\b/i,
    /\bguaranteed income|quick profit\b/i,
    /(гарантированн(ый|ого) доход|быстрый заработок|предоплат|переведи|удвоим сумму|инвестиц)/i,
  ],
  recruitment: [
    /\brecruit|recruitment|join our (group|cell|team)\b/i,
    /\bnew members needed|closed community|underground group\b/i,
    /\bjoin movement|tasks for members|radical team\b/i,
    /(вербовк|ищем людей|вступай|подпольн(ая|ую) ячейк|закрыт(ая|ую) групп|радикальн|нужны участники)/i,
  ],
  drugs: [
    /\b(drug|narcotic|stash|drop point|courier)\b/i,
    /\b(cocaine|heroin|amphetamine|meth|mdma|weed)\b/i,
    /\bdealer|selling\b/i,
    /(наркотик|закладк|кладмен|мефедрон|кокаин|героин|амфетамин|продам)/i,
  ],
  terrorism: [
    /\b(terror|terrorism|extremist)\b/i,
    /\b(explosive|bomb assembly|attack plan)\b/i,
    /\b(public place attack|mass attack|maximize panic)\b/i,
    /(теракт|взрывн(ое|ого) устройств|массов(ое|ого) нападени|атака на объект|ударим по толпе|максимальный ущерб)/i,
  ],
};
const CRITICAL_PATTERNS: Record<RiskCategory, Array<{ pattern: RegExp; score: number }>> = {
  toxicity: [
    { pattern: /\b(fuck|bitch|moron|idiot|trash)\b/i, score: 0.88 },
    { pattern: /(идиот|дебил|тварь|мразь|чмо|сука|урод|пидор)/i, score: 0.94 },
  ],
  threat: [
    { pattern: /\b(kill|shoot|stab|bomb|explode|attack)\b/i, score: 0.92 },
    { pattern: /(убью|взорву|зарежу|расстреляю|прямая угроза)/i, score: 0.96 },
  ],
  scam: [
    { pattern: /\b(scam|fraud|phishing|ponzi|fake investment)\b/i, score: 0.92 },
    { pattern: /\b(seed phrase|private key|passphrase|cvv|wallet connect)\b/i, score: 0.88 },
    { pattern: /(гарантированн(ый|ого) доход|быстрый заработок|предоплат|удвоим сумму|переведи (деньги|оплату|usdt))/i, score: 0.94 },
  ],
  recruitment: [
    { pattern: /\b(recruitment|recruit|join our cell|new members needed)\b/i, score: 0.9 },
    { pattern: /(вербовк|ищем людей|вступай в|подпольн(ая|ую) ячейк|закрыт(ую|ая) групп|радикальн)/i, score: 0.94 },
  ],
  drugs: [
    { pattern: /\b(drug|narcotic|cocaine|heroin|amphetamine|meth|mdma|stash)\b/i, score: 0.93 },
    { pattern: /(продам|закладк|кладмен|мефедрон|кокаин|героин|амфетамин|наркотик)/i, score: 0.95 },
  ],
  terrorism: [
    { pattern: /\b(terrorism|terror attack|explosive device|mass attack)\b/i, score: 0.96 },
    { pattern: /(теракт|взрывн(ое|ого) устройств|массов(ое|ого) нападени|атака на объект|оружие для атаки)/i, score: 0.97 },
  ],
};

function toStringValue(value: unknown, fallback: string): string {
  return typeof value === 'string' ? value : fallback;
}

function toBooleanValue(value: unknown, fallback: boolean): boolean {
  return typeof value === 'boolean' ? value : fallback;
}

function normalizeStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }
  const unique = new Set<string>();
  const result: string[] = [];
  for (const item of value) {
    if (typeof item !== 'string') continue;
    const normalized = item.trim();
    if (!normalized || unique.has(normalized)) continue;
    unique.add(normalized);
    result.push(normalized);
  }
  return result;
}

function toStringArray(value: unknown, fallback: string[]): string[] {
  const result = normalizeStringArray(value);
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

function normalizePercent(
  value: unknown,
  fallback: number,
  min = 0,
  max = 100
): number {
  const fallbackSafe = Math.min(max, Math.max(min, Math.round(fallback)));
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return fallbackSafe;
  }
  const normalized = value > 1 ? value / 100 : value;
  return Math.min(max, Math.max(min, Math.round(normalized * 100)));
}

function normalizeBoundedInteger(
  value: unknown,
  fallback: number,
  min: number,
  max: number
): number {
  const fallbackSafe = Math.min(max, Math.max(min, Math.round(fallback)));
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return fallbackSafe;
  }
  return Math.min(max, Math.max(min, Math.round(value)));
}

function normalizeCategoryThresholds(
  value: unknown,
  fallback: EngineCategoryThresholds
): EngineCategoryThresholds {
  const raw =
    typeof value === 'object' && value !== null ? (value as Record<string, unknown>) : {};
  return {
    toxicity: normalizeThresholdPercent(raw.toxicity, fallback.toxicity),
    threat: normalizeThresholdPercent(raw.threat, fallback.threat),
    scam: normalizeThresholdPercent(raw.scam, fallback.scam),
    recruitment: normalizeThresholdPercent(raw.recruitment, fallback.recruitment),
    drugs: normalizeThresholdPercent(raw.drugs, fallback.drugs),
    terrorism: normalizeThresholdPercent(raw.terrorism, fallback.terrorism),
  };
}

function normalizeAuthMode(value: unknown, fallback: TelegramAuthMode): TelegramAuthMode {
  return value === 'user' || value === 'bot' ? value : fallback;
}

function resolveTargetChatsForMode(
  source: Partial<Pick<PersistedAppSettings, 'targetChats' | 'botTargetChats' | 'userTargetChats'>>,
  mode: TelegramAuthMode,
  fallback: string[]
): string[] {
  const modeValue = mode === 'bot' ? source.botTargetChats : source.userTargetChats;
  const modeChats = normalizeStringArray(modeValue);
  if (modeChats.length > 0) {
    return modeChats;
  }

  const legacyChats = normalizeStringArray(source.targetChats);
  if (legacyChats.length > 0) {
    return legacyChats;
  }

  return [...fallback];
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
  const authMode = normalizeAuthMode(raw.authMode, fallback.authMode);
  const fallbackBotTargetChats = resolveTargetChatsForMode(
    fallback,
    'bot',
    DEFAULT_PERSISTED_SETTINGS.botTargetChats
  );
  const fallbackUserTargetChats = resolveTargetChatsForMode(
    fallback,
    'user',
    DEFAULT_PERSISTED_SETTINGS.userTargetChats
  );
  const legacyTargetChats = toStringArray(
    raw.targetChats,
    authMode === 'bot' ? fallbackBotTargetChats : fallbackUserTargetChats
  );
  const botTargetChats = Array.isArray(raw.botTargetChats)
    ? toStringArray(raw.botTargetChats, fallbackBotTargetChats)
    : authMode === 'bot'
      ? legacyTargetChats
      : fallbackBotTargetChats;
  const userTargetChats = Array.isArray(raw.userTargetChats)
    ? toStringArray(raw.userTargetChats, fallbackUserTargetChats)
    : authMode === 'user'
      ? legacyTargetChats
      : fallbackUserTargetChats;
  const targetChats = authMode === 'bot' ? botTargetChats : userTargetChats;
  const keywords = Array.isArray(raw.keywords) ? normalizeStringArray(raw.keywords) : fallback.keywords;
  const scamTriggers = Array.isArray(raw.scamTriggers)
    ? normalizeStringArray(raw.scamTriggers)
    : fallback.scamTriggers;
  const drugTriggers = Array.isArray(raw.drugTriggers)
    ? normalizeStringArray(raw.drugTriggers)
    : fallback.drugTriggers;
  const recruitmentTriggers = Array.isArray(raw.recruitmentTriggers)
    ? normalizeStringArray(raw.recruitmentTriggers)
    : fallback.recruitmentTriggers;
  const terrorismTriggers = Array.isArray(raw.terrorismTriggers)
    ? normalizeStringArray(raw.terrorismTriggers)
    : fallback.terrorismTriggers;
  const threatTriggers = Array.isArray(raw.threatTriggers)
    ? normalizeStringArray(raw.threatTriggers)
    : fallback.threatTriggers;
  const toxicityTriggers = Array.isArray(raw.toxicityTriggers)
    ? normalizeStringArray(raw.toxicityTriggers)
    : fallback.toxicityTriggers;
  const categoryThresholds = normalizeCategoryThresholds(
    raw.categoryThresholds,
    fallback.categoryThresholds
  );

  return {
    apiId: toStringValue(raw.apiId, fallback.apiId),
    apiHash: toStringValue(raw.apiHash, fallback.apiHash),
    authMode,
    botToken: toStringValue(raw.botToken, fallback.botToken),
    sessionString: toStringValue(raw.sessionString, fallback.sessionString),
    sessionName: toStringValue(raw.sessionName, fallback.sessionName),
    userAuthAllMessages: toBooleanValue(raw.userAuthAllMessages, fallback.userAuthAllMessages),
    botTargetChats,
    userTargetChats,
    targetChats,
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
    keywords,
    scamTriggers,
    drugTriggers,
    recruitmentTriggers,
    terrorismTriggers,
    threatTriggers,
    toxicityTriggers,
    mlModel,
    threatThreshold: normalizeThresholdPercent(raw.threatThreshold, fallback.threatThreshold),
    categoryThresholds,
    enableHeuristics: toBooleanValue(raw.enableHeuristics, fallback.enableHeuristics),
    enableCriticalPatterns: toBooleanValue(raw.enableCriticalPatterns, fallback.enableCriticalPatterns),
    modelWeight: normalizePercent(raw.modelWeight, fallback.modelWeight, 0, 100),
    heuristicWeight: normalizePercent(raw.heuristicWeight, fallback.heuristicWeight, 0, 100),
    modelTopK: normalizeBoundedInteger(raw.modelTopK, fallback.modelTopK, 1, 30),
    maxAnalysisChars: normalizeBoundedInteger(raw.maxAnalysisChars, fallback.maxAnalysisChars, 200, 4000),
    urlScamBoost: normalizePercent(raw.urlScamBoost, fallback.urlScamBoost, 0, 100),
    keywordHitBoost: normalizePercent(raw.keywordHitBoost, fallback.keywordHitBoost, 0, 100),
    criticalHitFloor: normalizePercent(raw.criticalHitFloor, fallback.criticalHitFloor, 0, 100),
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
  authMode: TelegramAuthMode;
  botToken: string;
  sessionString: string;
} {
  const raw = typeof source === 'object' && source !== null ? (source as Record<string, unknown>) : {};
  return {
    apiId: toStringValue(raw.apiId, persistedSettings.apiId).trim(),
    apiHash: toStringValue(raw.apiHash, persistedSettings.apiHash).trim(),
    authMode: normalizeAuthMode(raw.authMode, persistedSettings.authMode),
    botToken: toStringValue(raw.botToken, persistedSettings.botToken).trim(),
    sessionString: toStringValue(raw.sessionString, persistedSettings.sessionString).trim(),
  };
}

async function disposePendingSessionAuth(entry: PendingSessionAuth): Promise<void> {
  await entry.client.disconnect().catch(() => undefined);
}

function cleanupExpiredSessionAuthRequests(): void {
  const now = Date.now();
  for (const [requestId, entry] of pendingSessionAuth.entries()) {
    if (now - entry.createdAt > SESSION_AUTH_TTL_MS) {
      pendingSessionAuth.delete(requestId);
      void disposePendingSessionAuth(entry);
    }
  }
}

function takePendingSessionAuth(requestId: string): PendingSessionAuth | null {
  cleanupExpiredSessionAuthRequests();
  const entry = pendingSessionAuth.get(requestId);
  if (!entry) {
    return null;
  }
  pendingSessionAuth.delete(requestId);
  return entry;
}

function isDialogsForbiddenForBot(error: unknown): boolean {
  const message = (error as Error)?.message ?? '';
  return message.includes('BOT_METHOD_INVALID') || message.includes('messages.GetDialogs');
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

async function runWithUserSessionClient<T>(
  credentials: TelegramUserCredentials,
  reuseRunningClient: boolean,
  action: (clientRef: TelegramClient) => Promise<T>
): Promise<T> {
  if (reuseRunningClient && client && isRunning && runtimeAuthMode === 'user') {
    return action(client);
  }

  const tempSession = new StringSession(credentials.sessionString);
  const tempClient = new TelegramClient(tempSession, credentials.apiId, credentials.apiHash, {
    connectionRetries: 3,
  });

  await tempClient.connect();
  const isAuthorized = await tempClient.checkAuthorization();
  if (!isAuthorized) {
    throw new Error('Telegram user session is not authorized');
  }
  const me = await tempClient.getMe();
  if (me && typeof me === 'object' && 'bot' in me && (me as any).bot) {
    throw new Error('Session string belongs to a bot account. Switch Auth Mode to Bot Token.');
  }

  try {
    return await action(tempClient);
  } finally {
    await tempClient.disconnect().catch(() => undefined);
  }
}

function applyPersistedSettings(settings: PersistedAppSettings): void {
  selectedModelId = settings.mlModel;
  threatThreshold = settings.threatThreshold / 100;
  targetChats = resolveTargetChatsForMode(
    settings,
    settings.authMode,
    DEFAULT_PERSISTED_SETTINGS.targetChats
  );
  monitorAllUserAuthMessages = settings.userAuthAllMessages;
  runtimeAuthMode = settings.authMode;
}

let persistedSettings = loadPersistedSettings();
let selectedModelId = persistedSettings.mlModel;
let threatThreshold = persistedSettings.threatThreshold / 100;
let targetChats: string[] = resolveTargetChatsForMode(
  persistedSettings,
  persistedSettings.authMode,
  DEFAULT_PERSISTED_SETTINGS.targetChats
);
let monitorAllUserAuthMessages = persistedSettings.userAuthAllMessages;
let runtimeAuthMode: TelegramAuthMode = persistedSettings.authMode;
applyPersistedSettings(persistedSettings);
if (!fs.existsSync(SETTINGS_FILE)) {
  savePersistedSettings(persistedSettings);
}

function rateLimitActor(req: any): string {
  const username = req?.session?.user?.username ?? 'anonymous';
  const sessionId = req?.sessionID ?? 'no-session';
  const ip = req?.ip ?? req?.socket?.remoteAddress ?? 'unknown-ip';
  return `${username}|${sessionId}|${ip}`;
}

function consumeRateLimit(action: string, req: any, config: RateLimitConfig): { allowed: true } | { allowed: false; retryAfterMs: number } {
  const now = Date.now();
  const key = `${action}|${rateLimitActor(req)}`;
  const existing = rateLimitStore.get(key);

  if (!existing) {
    rateLimitStore.set(key, { windowStart: now, count: 1, blockedUntil: 0 });
    return { allowed: true };
  }

  if (existing.blockedUntil > now) {
    return { allowed: false, retryAfterMs: existing.blockedUntil - now };
  }

  if (now - existing.windowStart >= config.windowMs) {
    existing.windowStart = now;
    existing.count = 1;
    existing.blockedUntil = 0;
    rateLimitStore.set(key, existing);
    return { allowed: true };
  }

  if (existing.count >= config.max) {
    existing.blockedUntil = now + config.cooldownMs;
    rateLimitStore.set(key, existing);
    return { allowed: false, retryAfterMs: config.cooldownMs };
  }

  existing.count += 1;
  rateLimitStore.set(key, existing);
  return { allowed: true };
}

function withRateLimit(action: string, config: RateLimitConfig) {
  return (req, res, next) => {
    const result = consumeRateLimit(action, req, config);
    if (result.allowed) {
      next();
      return;
    }

    const retryAfterMs = 'retryAfterMs' in result ? result.retryAfterMs : config.cooldownMs;
    const retryAfterSec = Math.max(1, Math.ceil(retryAfterMs / 1000));
    res.setHeader('Retry-After', String(retryAfterSec));
    res.status(429).json({
      error: config.error,
      retryAfterMs,
      retryAfterSec,
      action,
    });
  };
}

const RL_LOGIN = withRateLimit('login', {
  windowMs: 10 * 60 * 1000,
  max: 10,
  cooldownMs: 5 * 60 * 1000,
  error: 'Too many login attempts. Please wait before trying again.',
});
const RL_SETTINGS_GET = withRateLimit('settings_get', {
  windowMs: 60 * 1000,
  max: 60,
  cooldownMs: 10 * 1000,
  error: 'Too many requests for settings.',
});
const RL_SETTINGS_SAVE = withRateLimit('settings_save', {
  windowMs: 60 * 1000,
  max: 6,
  cooldownMs: 20 * 1000,
  error: 'Too many settings save requests.',
});
const RL_SESSION_REQUEST_CODE = withRateLimit('session_request_code', {
  windowMs: 10 * 60 * 1000,
  max: 2,
  cooldownMs: 15 * 60 * 1000,
  error: 'Too many code requests. Please wait before requesting a new Telegram code.',
});
const RL_SESSION_COMPLETE = withRateLimit('session_complete', {
  windowMs: 5 * 60 * 1000,
  max: 8,
  cooldownMs: 60 * 1000,
  error: 'Too many session confirmation attempts.',
});
const RL_CHAT_SYNC = withRateLimit('chat_sync', {
  windowMs: 2 * 60 * 1000,
  max: 2,
  cooldownMs: 90 * 1000,
  error: 'Chat list sync cooldown is active. Try again later.',
});
const RL_ENGINE_CONTROL = withRateLimit('engine_control', {
  windowMs: 60 * 1000,
  max: 6,
  cooldownMs: 30 * 1000,
  error: 'Too many start/stop requests.',
});
const RL_ENGINE_TEST = withRateLimit('engine_test', {
  windowMs: 60 * 1000,
  max: 8,
  cooldownMs: 30 * 1000,
  error: 'Too many engine test requests.',
});
const RL_STATUS = withRateLimit('status', {
  windowMs: 60 * 1000,
  max: 180,
  cooldownMs: 10 * 1000,
  error: 'Status polling is too frequent.',
});
const RL_MESSAGES = withRateLimit('messages', {
  windowMs: 60 * 1000,
  max: 180,
  cooldownMs: 10 * 1000,
  error: 'Message polling is too frequent.',
});
const RL_STATS = withRateLimit('stats', {
  windowMs: 60 * 1000,
  max: 180,
  cooldownMs: 10 * 1000,
  error: 'Stats polling is too frequent.',
});

// --- AUTH API ---
app.post('/api/login', RL_LOGIN, (req, res) => {
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

app.get('/api/settings', isAdmin, RL_SETTINGS_GET, (_req, res) => {
  res.json(persistedSettings);
});

app.post('/api/settings', isAdmin, RL_SETTINGS_SAVE, (req, res) => {
  const merged = sanitizePersistedSettings(req.body, persistedSettings);
  persistedSettings = merged;
  applyPersistedSettings(merged);
  savePersistedSettings(merged);
  res.json({ status: 'saved', settings: merged });
});

app.post('/api/session/request-code', isAdmin, RL_SESSION_REQUEST_CODE, async (req, res) => {
  const apiIdValue = toStringValue(req.body?.apiId, persistedSettings.apiId).trim();
  const apiHash = toStringValue(req.body?.apiHash, persistedSettings.apiHash).trim();
  const phoneNumber = toStringValue(req.body?.phoneNumber, '').trim();

  const apiId = parsePositiveInteger(apiIdValue);
  if (!apiId || !apiHash || !phoneNumber) {
    return res.status(400).json({ error: 'API ID, API Hash and phone number are required' });
  }

  cleanupExpiredSessionAuthRequests();

  let tempClient: TelegramClient | null = null;
  try {
    const stringSession = new StringSession('');
    tempClient = new TelegramClient(stringSession, apiId, apiHash, { connectionRetries: 3 });
    await tempClient.connect();

    const sendCodeResult = await tempClient.sendCode({ apiId, apiHash }, phoneNumber);
    const requestId = randomUUID();
    pendingSessionAuth.set(requestId, {
      id: requestId,
      client: tempClient,
      stringSession,
      apiId,
      apiHash,
      phoneNumber,
      phoneCodeHash: sendCodeResult.phoneCodeHash,
      createdAt: Date.now(),
    });
    tempClient = null;

    res.json({
      requestId,
      isCodeViaApp: sendCodeResult.isCodeViaApp,
      expiresInSeconds: Math.round(SESSION_AUTH_TTL_MS / 1000),
    });
  } catch (error) {
    if (tempClient) {
      await tempClient.disconnect().catch(() => undefined);
    }
    res.status(500).json({ error: (error as Error).message });
  }
});

app.post('/api/session/complete', isAdmin, RL_SESSION_COMPLETE, async (req, res) => {
  const requestId = toStringValue(req.body?.requestId, '').trim();
  const phoneCode = toStringValue(req.body?.code, '').trim();
  const password = toStringValue(req.body?.password, '').trim();

  if (!requestId || !phoneCode) {
    return res.status(400).json({ error: 'requestId and code are required' });
  }

  const pending = takePendingSessionAuth(requestId);
  if (!pending) {
    return res.status(404).json({ error: 'Session request not found or expired. Request a new code.' });
  }

  try {
    let needsPassword = false;

    try {
      const signInResult = await pending.client.invoke(
        new Api.auth.SignIn({
          phoneNumber: pending.phoneNumber,
          phoneCodeHash: pending.phoneCodeHash,
          phoneCode,
        })
      );
      if (signInResult instanceof Api.auth.AuthorizationSignUpRequired) {
        await disposePendingSessionAuth(pending);
        return res.status(400).json({ error: 'Sign up flow is not supported in admin panel' });
      }
    } catch (error) {
      const message = (error as any)?.errorMessage ?? (error as Error).message ?? '';
      if (message.includes('SESSION_PASSWORD_NEEDED')) {
        needsPassword = true;
      } else {
        throw error;
      }
    }

    if (needsPassword) {
      if (!password) {
        pendingSessionAuth.set(requestId, {
          ...pending,
          createdAt: Date.now(),
        });
        return res.status(409).json({ requiresPassword: true, error: '2FA password is required' });
      }

      try {
        await pending.client.signInWithPassword(
          { apiId: pending.apiId, apiHash: pending.apiHash },
          {
            password: async () => password,
            onError: async () => true,
          }
        );
      } catch (error) {
        const message = (error as Error).message ?? '';
        if (message.includes('AUTH_USER_CANCEL')) {
          pendingSessionAuth.set(requestId, {
            ...pending,
            createdAt: Date.now(),
          });
          return res.status(400).json({ error: 'Invalid 2FA password' });
        }
        throw error;
      }
    }

    const authorized = await pending.client.checkAuthorization();
    if (!authorized) {
      throw new Error('Telegram authorization failed');
    }

    const sessionString = pending.stringSession.save();
    await disposePendingSessionAuth(pending);
    res.json({ sessionString });
  } catch (error) {
    await disposePendingSessionAuth(pending);
    res.status(500).json({ error: (error as Error).message });
  }
});

app.post('/api/telegram/chats', isAdmin, RL_CHAT_SYNC, async (req, res) => {
  const creds = resolveTelegramCredentials(req.body);

  try {
    let chats: TelegramChatSummary[] = [];

    if (creds.authMode === 'user') {
      const parsedApiId = parsePositiveInteger(creds.apiId);
      if (!parsedApiId || !creds.apiHash || !creds.sessionString) {
        return res.status(400).json({ error: 'API ID, API Hash and Session String are required for account mode' });
      }

      const reuseRunningClient =
        !!client &&
        isRunning &&
        runtimeAuthMode === 'user' &&
        creds.apiId === persistedSettings.apiId &&
        creds.apiHash === persistedSettings.apiHash &&
        creds.sessionString === persistedSettings.sessionString;

      try {
        chats = await runWithUserSessionClient(
          {
            apiId: parsedApiId,
            apiHash: creds.apiHash,
            sessionString: creds.sessionString,
          },
          reuseRunningClient,
          collectTelegramChats
        );
      } catch (error) {
        if (isDialogsForbiddenForBot(error)) {
          if (!creds.botToken) {
            return res.status(400).json({ error: 'Session belongs to bot account. Switch Auth Mode to Bot Token.' });
          }
          chats = await collectTelegramChatsViaBotApi(
            creds.botToken,
            resolveTargetChatsForMode(persistedSettings, 'bot', DEFAULT_PERSISTED_SETTINGS.botTargetChats)
          );
        } else {
          throw error;
        }
      }
    } else {
      if (!creds.botToken) {
        return res.status(400).json({ error: 'Bot Token is required for bot mode' });
      }
      chats = await collectTelegramChatsViaBotApi(
        creds.botToken,
        resolveTargetChatsForMode(persistedSettings, 'bot', DEFAULT_PERSISTED_SETTINGS.botTargetChats)
      );
    }

    res.json({ chats });
  } catch (error) {
    res.status(500).json({ error: (error as Error).message });
  }
});

function emptyRiskScores(): RiskScores {
  return {
    toxicity: 0,
    threat: 0,
    scam: 0,
    recruitment: 0,
    drugs: 0,
    terrorism: 0,
  };
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

function normalizeZeroShotScores(payload: unknown): LabelScore[] {
  if (!payload) return [];

  const candidate =
    Array.isArray(payload) && payload.length > 0
      ? payload[0]
      : payload;

  if (typeof candidate !== 'object' || candidate === null) {
    return [];
  }

  const entry = candidate as Record<string, unknown>;
  const labels = Array.isArray(entry.labels) ? entry.labels : [];
  const scores = Array.isArray(entry.scores) ? entry.scores : [];
  const count = Math.min(labels.length, scores.length);
  if (count <= 0) return [];

  const result: LabelScore[] = [];
  for (let index = 0; index < count; index += 1) {
    const label = labels[index];
    const score = scores[index];
    if (typeof label !== 'string') continue;
    result.push({
      label,
      score: clamp01(Number(score ?? 0)),
    });
  }

  return result;
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

type ModelScoreResult = {
  scores: RiskScores;
  safeScore: number;
};
type RuntimeEngineConfig = {
  enableHeuristics: boolean;
  enableCriticalPatterns: boolean;
  modelWeight: number;
  heuristicWeight: number;
  modelTopK: number;
  maxAnalysisChars: number;
  urlScamBoost: number;
  keywordHitBoost: number;
  criticalHitFloor: number;
  thresholds: RiskScores;
  keywords: string[];
  scamTriggers: string[];
  drugTriggers: string[];
  recruitmentTriggers: string[];
  terrorismTriggers: string[];
  threatTriggers: string[];
  toxicityTriggers: string[];
};
const SCAM_URL_CONTEXT_PATTERN = /(перевод|оплат|кошел|wallet|card|cvv|крипт|btc|usdt|бирж|p2p|инвест|доход|заработ)/i;

function toRatio(percent: number): number {
  return clamp01(percent / 100);
}

function normalizeTriggerList(value: string[]): string[] {
  const unique = new Set<string>();
  const result: string[] = [];
  for (const item of value) {
    const normalized = item.trim().toLowerCase();
    if (!normalized || unique.has(normalized)) continue;
    unique.add(normalized);
    result.push(normalized);
  }
  return result;
}

function normalizeWeights(modelWeightPercent: number, heuristicWeightPercent: number, useHeuristics: boolean): {
  modelWeight: number;
  heuristicWeight: number;
} {
  const modelWeight = clamp01(modelWeightPercent / 100);
  const heuristicWeight = useHeuristics ? clamp01(heuristicWeightPercent / 100) : 0;
  const total = modelWeight + heuristicWeight;
  if (total <= 0) {
    return useHeuristics
      ? { modelWeight: 0.55, heuristicWeight: 0.45 }
      : { modelWeight: 1, heuristicWeight: 0 };
  }
  return {
    modelWeight: modelWeight / total,
    heuristicWeight: heuristicWeight / total,
  };
}

function toRuntimeEngineConfig(source: PersistedAppSettings): RuntimeEngineConfig {
  const weights = normalizeWeights(source.modelWeight, source.heuristicWeight, source.enableHeuristics);
  return {
    enableHeuristics: source.enableHeuristics,
    enableCriticalPatterns: source.enableCriticalPatterns,
    modelWeight: weights.modelWeight,
    heuristicWeight: weights.heuristicWeight,
    modelTopK: source.modelTopK,
    maxAnalysisChars: source.maxAnalysisChars,
    urlScamBoost: toRatio(source.urlScamBoost),
    keywordHitBoost: toRatio(source.keywordHitBoost),
    criticalHitFloor: toRatio(source.criticalHitFloor),
    thresholds: {
      toxicity: normalizeThreshold(source.categoryThresholds.toxicity),
      threat: normalizeThreshold(source.categoryThresholds.threat),
      scam: normalizeThreshold(source.categoryThresholds.scam),
      recruitment: normalizeThreshold(source.categoryThresholds.recruitment),
      drugs: normalizeThreshold(source.categoryThresholds.drugs),
      terrorism: normalizeThreshold(source.categoryThresholds.terrorism),
    },
    keywords: normalizeTriggerList(source.keywords),
    scamTriggers: normalizeTriggerList(source.scamTriggers),
    drugTriggers: normalizeTriggerList(source.drugTriggers),
    recruitmentTriggers: normalizeTriggerList(source.recruitmentTriggers),
    terrorismTriggers: normalizeTriggerList(source.terrorismTriggers),
    threatTriggers: normalizeTriggerList(source.threatTriggers),
    toxicityTriggers: normalizeTriggerList(source.toxicityTriggers),
  };
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function hasTrigger(text: string, trigger: string): boolean {
  if (!trigger || trigger.length <= 2) return false;
  if (trigger.includes(' ')) {
    return text.includes(trigger);
  }
  const pattern = new RegExp(`(^|[^\\p{L}\\p{N}_])${escapeRegExp(trigger)}(?=$|[^\\p{L}\\p{N}_])`, 'iu');
  return pattern.test(text);
}

function countTriggerHits(text: string, triggers: string[]): number {
  let hits = 0;
  for (const trigger of triggers) {
    if (hasTrigger(text, trigger)) {
      hits += 1;
    }
  }
  return hits;
}

function scoreFromHits(base: number, hits: number, step: number, cap = 0.99): number {
  if (hits <= 0) return 0;
  return clamp01(Math.min(cap, base + (hits - 1) * step));
}

function extractModelScores(modelId: string, labels: LabelScore[]): ModelScoreResult {
  const scores = emptyRiskScores();
  const config = MODEL_CONFIGS[modelId] ?? MODEL_CONFIGS[DEFAULT_MODEL_ID];
  let safeScore = 0;

  for (const { label: rawLabel, score } of labels) {
    const label = normalizeLabelKey(rawLabel);

    if (isSafeLabel(label)) {
      safeScore = Math.max(safeScore, score);
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
    if (matchesAnyHint(label, config.labelHints.recruitment)) {
      scores.recruitment = Math.max(scores.recruitment, score);
    }
    if (matchesAnyHint(label, config.labelHints.drugs)) {
      scores.drugs = Math.max(scores.drugs, score);
    }
    if (matchesAnyHint(label, config.labelHints.terrorism)) {
      scores.terrorism = Math.max(scores.terrorism, score);
    }

    if (
      label === 'label-1' ||
      label.includes('toxic') ||
      label.includes('insult') ||
      label.includes('obscene') ||
      label.includes('offensive') ||
      label.includes('abuse')
    ) {
      scores.toxicity = Math.max(scores.toxicity, score);
    }
    if (label.includes('threat') || label.includes('danger') || label.includes('violence') || label.includes('kill')) {
      scores.threat = Math.max(scores.threat, score);
    }
    if (label.includes('scam') || label.includes('fraud') || label.includes('phishing') || label.includes('spam')) {
      scores.scam = Math.max(scores.scam, score);
    }
    if (label.includes('recruit') || label.includes('radical') || label.includes('extrem')) {
      scores.recruitment = Math.max(scores.recruitment, score);
    }
    if (label.includes('drug') || label.includes('narcotic') || label.includes('substance')) {
      scores.drugs = Math.max(scores.drugs, score);
    }
    if (label.includes('terror') || label.includes('terrorism')) {
      scores.terrorism = Math.max(scores.terrorism, score);
    }
  }

  return { scores, safeScore };
}

function extractZeroShotScores(config: ThreatModelConfig, labels: LabelScore[]): ModelScoreResult {
  const scores = emptyRiskScores();
  const zeroShot = config.zeroShot;
  if (!zeroShot) {
    return { scores, safeScore: 0 };
  }

  const byLabel = new Map<string, number>();
  for (const labelEntry of labels) {
    byLabel.set(normalizeLabelKey(labelEntry.label), labelEntry.score);
  }

  for (const category of RISK_CATEGORIES) {
    const candidateLabel = zeroShot.candidateLabels[category];
    const score = byLabel.get(normalizeLabelKey(candidateLabel)) ?? 0;
    scores[category] = clamp01(score);
  }

  const topScore = RISK_CATEGORIES.reduce((max, category) => Math.max(max, scores[category]), 0);
  return {
    scores,
    safeScore: clamp01(1 - topScore),
  };
}

async function getClassifier(modelId: string): Promise<TextClassifier> {
  const config = MODEL_CONFIGS[modelId] ?? MODEL_CONFIGS[DEFAULT_MODEL_ID];
  let classifierPromise = classifierCache.get(config.id);

  if (!classifierPromise) {
    classifierPromise = (async () => {
      console.log(`Loading local ONNX model: ${config.name} (${config.repo})`);
      const classifier = await pipeline(config.task, config.repo, config.inferenceOptions ?? {});
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

async function requestModelScores(modelId: string, text: string): Promise<ModelScoreResult> {
  const modelConfig = MODEL_CONFIGS[modelId] ?? MODEL_CONFIGS[DEFAULT_MODEL_ID];
  const classifier = await getClassifier(modelId);
  const preparedText = text.slice(0, 1000);

  if (modelConfig.task === 'zero-shot-classification') {
    const zeroShot = modelConfig.zeroShot;
    if (!zeroShot) return { scores: emptyRiskScores(), safeScore: 0 };
    const payload = await classifier(
      preparedText,
      Object.values(zeroShot.candidateLabels),
      {
        multi_label: zeroShot.multiLabel ?? true,
        hypothesis_template: zeroShot.hypothesisTemplate ?? 'This text is about {}.',
      }
    );
    const labels = normalizeZeroShotScores(payload);
    return extractZeroShotScores(modelConfig, labels);
  }

  const payload = await classifier(preparedText, { top_k: 10 });
  const labels = normalizeLabelScores(payload);
  return extractModelScores(modelId, labels);
}

async function analyzeThreat(text: string): Promise<{ type: ThreatType; score: number }> {
  const result = await analyzeThreatDetailed(text);
  return { type: result.type, score: result.score };
}

function enhancedHeuristicScores(text: string, config: RuntimeEngineConfig): RiskScores {
  const scores = emptyRiskScores();
  const normalized = text.toLowerCase();

  if (config.enableHeuristics) {
    (Object.keys(HEURISTIC_PATTERNS) as RiskCategory[]).forEach((category) => {
      const hits = HEURISTIC_PATTERNS[category].reduce((sum, pattern) => sum + (pattern.test(text) ? 1 : 0), 0);
      scores[category] = clamp01(Math.min(0.9, hits * 0.22));
    });

    const toxicityHits = countTriggerHits(normalized, config.toxicityTriggers);
    const threatHits = countTriggerHits(normalized, config.threatTriggers);
    const scamHits = countTriggerHits(normalized, config.scamTriggers);
    const recruitmentHits = countTriggerHits(normalized, config.recruitmentTriggers);
    const drugHits = countTriggerHits(normalized, config.drugTriggers);
    const terrorismHits = countTriggerHits(normalized, config.terrorismTriggers);
    const keywordHits = countTriggerHits(normalized, config.keywords);

    if (toxicityHits > 0) {
      scores.toxicity = Math.max(scores.toxicity, scoreFromHits(0.52, toxicityHits, 0.11, 0.96));
    }
    if (threatHits > 0) {
      scores.threat = Math.max(scores.threat, scoreFromHits(0.58, threatHits, 0.11, 0.98));
    }
    if (scamHits > 0) {
      scores.scam = Math.max(scores.scam, scoreFromHits(0.56, scamHits, 0.1, 0.98));
    }
    if (recruitmentHits > 0) {
      scores.recruitment = Math.max(scores.recruitment, scoreFromHits(0.66, recruitmentHits, 0.1, 0.99));
      scores.threat = Math.max(scores.threat, scoreFromHits(0.58, recruitmentHits, 0.08, 0.95));
    }
    if (drugHits > 0) {
      scores.drugs = Math.max(scores.drugs, scoreFromHits(0.74, drugHits, 0.08, 0.99));
      scores.threat = Math.max(scores.threat, scoreFromHits(0.62, drugHits, 0.08, 0.95));
    }
    if (terrorismHits > 0) {
      scores.terrorism = Math.max(scores.terrorism, scoreFromHits(0.78, terrorismHits, 0.07, 0.99));
      scores.threat = Math.max(scores.threat, scoreFromHits(0.68, terrorismHits, 0.08, 0.97));
    }
    if (keywordHits > 0) {
      const boosted = clamp01(Math.max(scores.scam, 0.35) + keywordHits * config.keywordHitBoost);
      scores.scam = Math.max(scores.scam, boosted);
    }
  }

  if (config.enableCriticalPatterns) {
    (Object.keys(CRITICAL_PATTERNS) as RiskCategory[]).forEach((category) => {
      for (const rule of CRITICAL_PATTERNS[category]) {
        if (rule.pattern.test(text)) {
          scores[category] = Math.max(scores[category], rule.score, config.criticalHitFloor);
        }
      }
    });
  }

  if (/https?:\/\//i.test(text) && SCAM_URL_CONTEXT_PATTERN.test(text)) {
    scores.scam = Math.max(scores.scam, clamp01(0.6 + config.urlScamBoost));
  }

  return scores;
}

async function requestModelScoresWithConfig(
  modelId: string,
  text: string,
  config: RuntimeEngineConfig
): Promise<ModelScoreResult> {
  const modelConfig = MODEL_CONFIGS[modelId] ?? MODEL_CONFIGS[DEFAULT_MODEL_ID];
  const classifier = await getClassifier(modelId);
  const preparedText = text.slice(0, config.maxAnalysisChars);

  if (modelConfig.task === 'zero-shot-classification') {
    const zeroShot = modelConfig.zeroShot;
    if (!zeroShot) return { scores: emptyRiskScores(), safeScore: 0 };
    const payload = await classifier(
      preparedText,
      Object.values(zeroShot.candidateLabels),
      {
        multi_label: zeroShot.multiLabel ?? true,
        hypothesis_template: zeroShot.hypothesisTemplate ?? 'This text is about {}.',
      }
    );
    const labels = normalizeZeroShotScores(payload);
    if (labels.length === 0) {
      throw new Error('Zero-shot inference returned empty labels');
    }
    return extractZeroShotScores(modelConfig, labels);
  }

  const payload = await classifier(preparedText, { top_k: config.modelTopK });
  const labels = normalizeLabelScores(payload);
  return extractModelScores(modelId, labels);
}

function emptyThresholdScores(): RiskScores {
  return emptyRiskScores();
}

function resolveCategoryThresholds(config: RuntimeEngineConfig, globalThreshold: number): RiskScores {
  const resolved = emptyRiskScores();
  for (const category of RISK_CATEGORIES) {
    resolved[category] = config.thresholds[category] > 0 ? config.thresholds[category] : globalThreshold;
  }
  return resolved;
}

function blendScores(model: RiskScores, heuristic: RiskScores, config: RuntimeEngineConfig): RiskScores {
  const blended = emptyRiskScores();
  for (const category of RISK_CATEGORIES) {
    blended[category] = clamp01(
      model[category] * config.modelWeight + heuristic[category] * config.heuristicWeight
    );
  }
  return blended;
}

function applyCriticalHeuristicOverride(
  blended: RiskScores,
  heuristic: RiskScores,
  config: RuntimeEngineConfig
): RiskScores {
  const resolved = { ...blended };
  if (!config.enableCriticalPatterns) {
    return resolved;
  }

  // Keep explicit critical hits decisive even if model confidence is low.
  for (const category of RISK_CATEGORIES) {
    if (heuristic[category] >= config.criticalHitFloor) {
      resolved[category] = Math.max(resolved[category], heuristic[category]);
    }
  }

  return resolved;
}

async function analyzeThreatDetailed(
  text: string,
  sourceSettings: PersistedAppSettings = persistedSettings
): Promise<AnalyzeThreatResult> {
  if (!text || text.trim() === '') {
    return {
      type: 'safe',
      score: 0.99,
      scores: emptyRiskScores(),
      heuristicScores: emptyRiskScores(),
      modelScores: emptyRiskScores(),
      thresholds: emptyThresholdScores(),
    };
  }

  const normalizedText = text.trim();
  const modelId = MODEL_CONFIGS[sourceSettings.mlModel] ? sourceSettings.mlModel : DEFAULT_MODEL_ID;
  const config = toRuntimeEngineConfig(sourceSettings);
  const globalThreshold = normalizeThreshold(sourceSettings.threatThreshold);
  const thresholds = resolveCategoryThresholds(config, globalThreshold);
  const heuristic = enhancedHeuristicScores(normalizedText, config);
  let model = emptyRiskScores();
  let safeLabelScore = 0;

  try {
    const modelResult = await requestModelScoresWithConfig(modelId, normalizedText, config);
    model = modelResult.scores;
    safeLabelScore = modelResult.safeScore;
  } catch (error) {
    console.warn(`Inference fallback to heuristics: ${(error as Error).message}`);
  }

  // Strong safe signal lowers model confidence to reduce false positives.
  const safeAttenuation = clamp01(1 - safeLabelScore * 0.65);
  const modelAdjusted = emptyRiskScores();
  for (const category of RISK_CATEGORIES) {
    modelAdjusted[category] = clamp01(model[category] * safeAttenuation);
  }
  const blended = blendScores(modelAdjusted, heuristic, config);
  const combined = applyCriticalHeuristicOverride(blended, heuristic, config);

  const ranked = (Object.entries(combined) as [RiskCategory, number][])
    .sort((a, b) => b[1] - a[1]);
  const triggered = ranked.find(([category, score]) => score >= thresholds[category]);
  if (triggered) {
    const [topCategory, topScore] = triggered;
    return {
      type: topCategory,
      score: clamp01(topScore),
      scores: combined,
      heuristicScores: heuristic,
      modelScores: modelAdjusted,
      thresholds,
    };
  }

  const topScore = ranked[0]?.[1] ?? 0;
  const safeConfidence = clamp01(Math.max(0.05, 1 - topScore));
  return {
    type: 'safe',
    score: safeConfidence,
    scores: combined,
    heuristicScores: heuristic,
    modelScores: modelAdjusted,
    thresholds,
  };
}

app.post('/api/engine/test', isAdmin, RL_ENGINE_TEST, async (req, res) => {
  try {
    const settingsRaw =
      typeof req.body?.settings === 'object' && req.body.settings !== null
        ? (req.body.settings as Record<string, unknown>)
        : {};
    const testSettings = sanitizePersistedSettings(
      {
        ...persistedSettings,
        ...settingsRaw,
      },
      persistedSettings
    );

    const presetRaw = toStringValue(req.body?.preset, 'all').trim().toLowerCase();
    const presetCandidates: Array<Exclude<EngineSelfTestPreset, 'all'>> = [
      'toxicity',
      'threat',
      'scam',
      'recruitment',
      'drugs',
      'terrorism',
    ];
    const selectedPreset: EngineSelfTestPreset = presetCandidates.includes(presetRaw as Exclude<EngineSelfTestPreset, 'all'>)
      ? (presetRaw as Exclude<EngineSelfTestPreset, 'all'>)
      : 'all';

    const incomingMessages = Array.isArray(req.body?.messages) ? req.body.messages : [];
    const customMessages = incomingMessages
      .filter((value): value is string => typeof value === 'string')
      .map((value) => value.trim())
      .filter((value) => value.length > 0)
      .slice(0, 80);

    const presetMessages =
      selectedPreset === 'all'
        ? ENGINE_SELF_TEST_MESSAGES
        : ENGINE_SELF_TEST_PRESETS[selectedPreset];

    const tests = customMessages.length > 0
      ? customMessages.map((text) => ({ text, expected: null as ThreatType | null, scenario: 'custom' }))
      : presetMessages.map((entry) => ({ ...entry }));

    const toPercentScores = (scores: RiskScores): Record<RiskCategory, number> => {
      const result = {} as Record<RiskCategory, number>;
      for (const category of RISK_CATEGORIES) {
        result[category] = Math.round(scores[category] * 100);
      }
      return result;
    };

    const results: Array<{
      text: string;
      expected: ThreatType | null;
      scenario: string;
      type: ThreatType;
      confidence: number;
      scores: Record<RiskCategory, number>;
      heuristicScores: Record<RiskCategory, number>;
      modelScores: Record<RiskCategory, number>;
      thresholds: Record<RiskCategory, number>;
    }> = [];
    const summary: Record<ThreatType, number> = {
      safe: 0,
      toxicity: 0,
      threat: 0,
      scam: 0,
      recruitment: 0,
      drugs: 0,
      terrorism: 0,
    };

    for (const test of tests) {
      const analysis = await analyzeThreatDetailed(test.text, testSettings);
      summary[analysis.type as keyof typeof summary] += 1;

      results.push({
        text: test.text,
        expected: test.expected,
        scenario: test.scenario,
        type: analysis.type,
        confidence: Math.round(analysis.score * 100),
        scores: toPercentScores(analysis.scores),
        heuristicScores: toPercentScores(analysis.heuristicScores),
        modelScores: toPercentScores(analysis.modelScores),
        thresholds: toPercentScores(analysis.thresholds),
      });
    }

    res.json({
      model: testSettings.mlModel,
      threshold: Math.round(normalizeThreshold(testSettings.threatThreshold) * 100),
      count: results.length,
      usedDefaultDataset: customMessages.length === 0,
      usedPreset: customMessages.length === 0 ? selectedPreset : 'custom',
      summary,
      results,
    });
  } catch (error) {
    res.status(500).json({ error: (error as Error).message });
  }
});

app.post('/api/start', isAdmin, RL_ENGINE_CONTROL, async (req, res) => {
  if (isRunning) return res.json({ status: 'already running' });
  
  const {
    apiId,
    apiHash,
    authMode,
    botToken,
    sessionString,
    userAuthAllMessages,
    chats,
    model,
    threatThreshold: requestedThreshold
  } = req.body;
  const resolvedApiId = toStringValue(apiId, persistedSettings.apiId).trim();
  const resolvedApiHash = toStringValue(apiHash, persistedSettings.apiHash).trim();
  const resolvedAuthMode = normalizeAuthMode(authMode, persistedSettings.authMode);
  const resolvedBotToken = toStringValue(botToken, persistedSettings.botToken).trim();
  const resolvedSessionString = toStringValue(sessionString, persistedSettings.sessionString).trim();
  const resolvedUserAuthAllMessages = toBooleanValue(userAuthAllMessages, persistedSettings.userAuthAllMessages);
  const persistedModeChats = resolveTargetChatsForMode(
    persistedSettings,
    resolvedAuthMode,
    DEFAULT_PERSISTED_SETTINGS.targetChats
  );
  const resolvedChats = Array.isArray(chats)
    ? toStringArray(chats, persistedModeChats)
    : persistedModeChats;
  const resolvedModel = typeof model === 'string' && MODEL_CONFIGS[model] ? model : persistedSettings.mlModel;
  const resolvedThreshold =
    requestedThreshold === undefined
      ? persistedSettings.threatThreshold / 100
      : normalizeThreshold(requestedThreshold);

  if (!resolvedApiId || !resolvedApiHash) {
    return res.status(400).json({ error: 'API ID and API Hash are required' });
  }
  const parsedApiId = parsePositiveInteger(resolvedApiId);
  if (!parsedApiId) {
    return res.status(400).json({ error: 'API ID must be a positive integer' });
  }

  if (resolvedAuthMode === 'bot' && !resolvedBotToken) {
    return res.status(400).json({ error: 'Bot Token is required for bot mode' });
  }

  if (resolvedAuthMode === 'user' && !resolvedSessionString) {
    return res.status(400).json({ error: 'Session String is required for account mode' });
  }

  persistedSettings = sanitizePersistedSettings(
    {
      ...persistedSettings,
      apiId: resolvedApiId,
      apiHash: resolvedApiHash,
      authMode: resolvedAuthMode,
      botToken: resolvedBotToken,
      sessionString: resolvedSessionString,
      userAuthAllMessages: resolvedUserAuthAllMessages,
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

    const stringSession = new StringSession(resolvedAuthMode === 'user' ? resolvedSessionString : '');
    client = new TelegramClient(stringSession, parsedApiId, resolvedApiHash, {
      connectionRetries: 5,
    });

    if (resolvedAuthMode === 'bot') {
      await client.start({
        botAuthToken: resolvedBotToken,
      });
    } else {
      await client.connect();
      const isAuthorized = await client.checkAuthorization();
      if (!isAuthorized) {
        throw new Error('Telegram user session is not authorized. Generate a valid String Session and save it.');
      }
      const me = await client.getMe();
      if (me && typeof me === 'object' && 'bot' in me && (me as any).bot) {
        throw new Error('Session string belongs to a bot account. Switch Auth Mode to Bot Token.');
      }
    }

    if (resolvedAuthMode === 'user') {
      const currentSession = stringSession.save();
      if (currentSession && currentSession !== persistedSettings.sessionString) {
        persistedSettings = sanitizePersistedSettings(
          {
            ...persistedSettings,
            sessionString: currentSession,
          },
          persistedSettings
        );
        applyPersistedSettings(persistedSettings);
        savePersistedSettings(persistedSettings);
      }
    }

    isRunning = true;
    runtimeAuthMode = resolvedAuthMode;
    monitorAllUserAuthMessages = resolvedUserAuthAllMessages;
    const shouldMonitorAllDialogs = resolvedAuthMode === 'user' && monitorAllUserAuthMessages;
    const eventChatFilter = shouldMonitorAllDialogs
      ? undefined
      : (targetChats.length > 0 ? targetChats : undefined);
    
    client.addEventHandler(async (event) => {
      const message = event.message;
      const text = message.text || '';
      
      const sender = await message.getSender();
      const senderName = sender && 'username' in sender && sender.username ? `@${sender.username}` : 'Unknown';
      
      const chat = await message.getChat();
      const chatTitle = chat && 'title' in chat ? chat.title : 'Unknown Chat';
      const chatId =
        chat && typeof chat === 'object' && 'id' in chat && (chat as any).id !== undefined
          ? String((chat as any).id)
          : null;
      const messageTs =
        typeof message.date === 'number' && Number.isFinite(message.date)
          ? Math.floor(message.date)
          : Math.floor(Date.now() / 1000);
      
      const analysis = await analyzeThreat(text);
      storeMessage({
        telegramMessageId: typeof message.id === 'number' && Number.isFinite(message.id) ? message.id : null,
        telegramChatId: chatId,
        messageTs,
        chat: chatTitle,
        sender: senderName,
        text,
        type: analysis.type,
        score: analysis.score,
      });
    }, new NewMessage({ chats: eventChatFilter }));
    
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

app.post('/api/stop', isAdmin, RL_ENGINE_CONTROL, async (req, res) => {
  if (client) {
    await client.disconnect();
    client = null;
    isRunning = false;
  }
  res.json({ status: 'stopped' });
});

app.get('/api/status', isAuthenticated, RL_STATUS, (req, res) => {
  res.json({
    isRunning,
    model: selectedModelId,
    threshold: threatThreshold,
  });
});

app.get('/api/messages', isAuthenticated, RL_MESSAGES, (req, res) => {
  const limitRaw = Number(req.query?.limit ?? MAX_RECENT_MESSAGES);
  const limit = Number.isFinite(limitRaw) ? Math.floor(limitRaw) : MAX_RECENT_MESSAGES;
  res.json(readRecentMessages(limit));
});

app.get('/api/stats', isAuthenticated, RL_STATS, (req, res) => {
  res.json(readThreatStats());
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
