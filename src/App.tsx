import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Link, Navigate, Outlet } from 'react-router-dom';
import LoginPage from './LoginPage';
import { 
  Shield, Activity, Settings, Terminal, Play, Square, 
  Plus, Trash2, Save, AlertTriangle, MessageSquare, FileText, RefreshCw,
  Image as ImageIcon, Video, Link as LinkIcon, Globe, Lock, Database, Cpu
} from 'lucide-react';
import { 
  PieChart, Pie, Cell, ResponsiveContainer, Tooltip as RechartsTooltip, Legend 
} from 'recharts';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

// --- UTILITY ---
function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

// --- AUTH ---
const AuthContext = React.createContext<any>(null);

const AuthProvider = ({ children }: { children: React.ReactNode }) => {
  const [user, setUser] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const checkUser = async () => {
      try {
        const res = await fetch('/api/user');
        if (res.ok) {
          const userData = await res.json();
          setUser(userData);
        }
      } catch (err) {
        console.error('Failed to fetch user', err);
      } finally {
        setLoading(false);
      }
    };
    checkUser();
  }, []);

  const login = async (username, password) => {
    const res = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    if (res.ok) {
      const userData = await res.json();
      setUser(userData);
      return true;
    }
    return false;
  };

  const logout = async () => {
    await fetch('/api/logout', { method: 'POST' });
    setUser(null);
  };

  const value = { user, login, logout, isAuthenticated: !!user, loading };

  return <AuthContext.Provider value={value}>{!loading && children}</AuthContext.Provider>;
};

export const useAuth = () => {
  return React.useContext(AuthContext);
};

const PrivateRoute = () => {
  const { isAuthenticated, loading } = useAuth();
  if (loading) return <div>Loading...</div>; // Or a spinner
  return isAuthenticated ? <Outlet /> : <Navigate to="/login" />;
};


// --- MOCK DATA ---
const THREAT_TYPES = ['safe', 'toxicity', 'threat', 'scam', 'recruitment', 'drugs', 'terrorism'];
const THREAT_COLORS = {
  safe: '#10b981', // emerald-500
  toxicity: '#f59e0b', // amber-500
  threat: '#ef4444', // red-500
  scam: '#8b5cf6', // violet-500
  recruitment: '#0ea5e9', // sky-500
  drugs: '#eab308', // yellow-500
  terrorism: '#dc2626', // red-600
};
const THREAT_LABELS = {
  safe: 'Safe',
  toxicity: 'Toxicity',
  threat: 'Threat',
  scam: 'Scam',
  recruitment: 'Recruitment',
  drugs: 'Drugs',
  terrorism: 'Terrorism',
} as const;

type ModelOption = {
  id: string;
  name: string;
  summary: string;
  bestFor: string;
};

const MODEL_OPTIONS: ModelOption[] = [
  {
    id: 'local/rubert-tiny-balanced',
    name: 'RuBERT Tiny ONNX (Balanced)',
    summary: 'Default local Russian model. Best balance between speed and confidence quality.',
    bestFor: 'General use on CPU VPS',
  },
  {
    id: 'local/rubert-tiny-quantized',
    name: 'RuBERT Tiny ONNX (Quantized)',
    summary: 'Quantized ONNX profile with lower RAM usage and faster inference.',
    bestFor: 'Small server footprint',
  },
  {
    id: 'local/rubert-tiny-fp16',
    name: 'RuBERT Tiny ONNX (FP16 optimized)',
    summary: 'Alternative ONNX export that may improve throughput on some CPUs.',
    bestFor: 'Maximum throughput testing',
  },
  {
    id: 'hf/bert-mini-toxicity-quant',
    name: 'BERT Mini Toxicity (Multilingual Quantized)',
    summary: 'Compact multilingual toxicity model with low RAM usage.',
    bestFor: 'Minimal VPS resources',
  },
  {
    id: 'hf/bert-small-toxicity-quant',
    name: 'BERT Small Toxicity (Multilingual Quantized)',
    summary: 'Balanced multilingual toxicity model with higher quality than mini.',
    bestFor: 'Balanced quality/speed',
  },
  {
    id: 'hf/distilbert-multilingual-toxicity-quant',
    name: 'DistilBERT Multilingual Toxicity (Quantized)',
    summary: 'Broader multilingual coverage for mixed-language chats.',
    bestFor: 'Mixed RU/EN chat streams',
  },
  {
    id: 'zero-shot/xenova-mdeberta-v3-xnli',
    name: 'mDeBERTa-v3 XNLI (Zero-Shot)',
    summary: 'Zero-shot multilingual NLI model for custom moderation categories.',
    bestFor: 'Scam/drugs/recruitment/terrorism category detection',
  },
  {
    id: 'zero-shot/mdeberta-v3-mnli-xnli',
    name: 'mDeBERTa-v3 MNLI/XNLI (Zero-Shot)',
    summary: 'Stronger multilingual zero-shot model, heavier than toxicity classifiers.',
    bestFor: 'Higher quality on diverse category semantics',
  },
];

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
  'переведи usdt',
  'seed phrase',
  'сид фраза',
  'wallet connect',
  'предоплата',
  'арбитраж',
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
  'кокаин',
  'героин',
  'марихуана',
  'спайс',
  'соль',
  'mdma',
  'экстази',
];
const DEFAULT_RECRUITMENT_TRIGGERS = [
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
  'бомба',
  'оружие',
  'угроза',
  'теракт',
  'нападу',
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
];

const ENGINE_RISK_KEYS: Array<keyof EngineRiskScores> = [
  'toxicity',
  'threat',
  'scam',
  'recruitment',
  'drugs',
  'terrorism',
];
type EngineSelfTestPreset = 'all' | 'recruitment' | 'drugs' | 'terrorism';
type EngineSelfTestCategory = Exclude<EngineSelfTestPreset, 'all'>;

const ENGINE_SELF_TEST_PRESET_OPTIONS: Array<{
  id: EngineSelfTestPreset;
  label: string;
  description: string;
}> = [
  {
    id: 'all',
    label: 'All Categories',
    description: 'Runs built-in messages from all preset categories.',
  },
  {
    id: 'recruitment',
    label: 'Recruitment',
    description: 'Messages about joining closed groups, cells, or coordinated teams.',
  },
  {
    id: 'drugs',
    label: 'Drugs',
    description: 'Messages about selling narcotics, stash drops, and courier tasks.',
  },
  {
    id: 'terrorism',
    label: 'Terrorism',
    description: 'Messages about attacks, explosives, and violent extremist actions.',
  },
];

const SELF_TEST_PRESET_MESSAGES: Record<EngineSelfTestCategory, string[]> = {
  recruitment: [
    'Join our closed cell, we need new members for operations.',
    'Recruitment to underground group is open, DM for tasks.',
    'Need motivated fighters, training and missions start immediately.',
    'We are forming a radical team, only trusted people needed.',
  ],
  drugs: [
    'Selling meph and amphetamine, fast delivery and hidden drop points.',
    'Need a stash courier for daily drug drops, good payout.',
    'Cocaine and mdma available, write for coordinates and price.',
    'New stash location posted, payment first then coordinates.',
  ],
  terrorism: [
    'Preparing an attack with explosives in a public location.',
    'Need weapons and people for a terror operation this week.',
    'Plan is to maximize panic and damage during the strike.',
    'Instructions for bomb assembly and target timing will follow.',
  ],
};

type SettingsState = {
  apiId: string;
  apiHash: string;
  authMode: 'bot' | 'user';
  botToken: string;
  sessionString: string;
  sessionName: string;
  userAuthAllMessages: boolean;
  botTargetChats: string[];
  userTargetChats: string[];
  targetChats: string[];
  newChatInput: string;
  proxyEnabled: boolean;
  proxyType: string;
  proxyHost: string;
  proxyPort: string;
  proxyUser: string;
  proxyPass: string;
  downloadMedia: boolean;
  mediaTypes: { photo: boolean; video: boolean; document: boolean; audio: boolean };
  keywords: string[];
  newKeywordInput: string;
  scamTriggers: string[];
  drugTriggers: string[];
  recruitmentTriggers: string[];
  terrorismTriggers: string[];
  threatTriggers: string[];
  toxicityTriggers: string[];
  mlModel: string;
  threatThreshold: number;
  categoryThresholds: {
    toxicity: number;
    threat: number;
    scam: number;
    recruitment: number;
    drugs: number;
    terrorism: number;
  };
  enableHeuristics: boolean;
  enableCriticalPatterns: boolean;
  modelWeight: number;
  heuristicWeight: number;
  modelTopK: number;
  maxAnalysisChars: number;
  urlScamBoost: number;
  keywordHitBoost: number;
  criticalHitFloor: number;
};

type AvailableTelegramChat = {
  id: string;
  title: string;
  username: string | null;
  type: 'group' | 'supergroup' | 'channel';
  avatar: string | null;
};
type ThreatLabel = 'safe' | 'toxicity' | 'threat' | 'scam' | 'recruitment' | 'drugs' | 'terrorism';
type EngineRiskScores = {
  toxicity: number;
  threat: number;
  scam: number;
  recruitment: number;
  drugs: number;
  terrorism: number;
};
type EngineTestResult = {
  text: string;
  expected: string | null;
  scenario: string;
  type: ThreatLabel;
  confidence: number;
  scores: EngineRiskScores;
  heuristicScores: EngineRiskScores;
  modelScores: EngineRiskScores;
  thresholds: EngineRiskScores;
};
type CooldownKey = 'saveSettings' | 'syncChats' | 'sessionCode' | 'sessionConfirm' | 'engineControl' | 'engineTest';
type ActiveTab = 'dashboard' | 'agents' | 'engine' | 'proxy' | 'logs';

const DEFAULT_SETTINGS: SettingsState = {
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
  newChatInput: '',
  proxyEnabled: false,
  proxyType: 'SOCKS5',
  proxyHost: '127.0.0.1',
  proxyPort: '1080',
  proxyUser: '',
  proxyPass: '',
  downloadMedia: false,
  mediaTypes: { photo: true, video: false, document: false, audio: false },
  keywords: ['crypto', 'invest', 'wallet', 'usdt', 'btc', 'перевод', 'кошелек'],
  newKeywordInput: '',
  scamTriggers: [...DEFAULT_SCAM_TRIGGERS],
  drugTriggers: [...DEFAULT_DRUG_TRIGGERS],
  recruitmentTriggers: [...DEFAULT_RECRUITMENT_TRIGGERS],
  terrorismTriggers: [...DEFAULT_TERRORISM_TRIGGERS],
  threatTriggers: [...DEFAULT_THREAT_TRIGGERS],
  toxicityTriggers: [...DEFAULT_TOXICITY_TRIGGERS],
  mlModel: MODEL_OPTIONS[0].id,
  threatThreshold: 75,
  categoryThresholds: { toxicity: 72, threat: 72, scam: 70, recruitment: 74, drugs: 74, terrorism: 76 },
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

function normalizeChatList(value: unknown): string[] {
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

function toChatList(value: unknown, fallback: string[]): string[] {
  const normalized = normalizeChatList(value);
  return normalized.length > 0 ? normalized : fallback;
}

function resolveTargetChatsForMode(
  source: Partial<Pick<SettingsState, 'targetChats' | 'botTargetChats' | 'userTargetChats'>>,
  mode: 'bot' | 'user',
  fallback: string[]
): string[] {
  const modeValue = mode === 'bot' ? source.botTargetChats : source.userTargetChats;
  const modeChats = normalizeChatList(modeValue);
  if (modeChats.length > 0) {
    return modeChats;
  }

  const legacyChats = normalizeChatList(source.targetChats);
  if (legacyChats.length > 0) {
    return legacyChats;
  }

  return [...fallback];
}

function normalizeTriggerArray(value: unknown, fallback: string[]): string[] {
  if (!Array.isArray(value)) return [...fallback];
  const unique = new Set<string>();
  const result: string[] = [];
  for (const item of value) {
    if (typeof item !== 'string') continue;
    const normalized = item.trim();
    if (!normalized || unique.has(normalized.toLowerCase())) continue;
    unique.add(normalized.toLowerCase());
    result.push(normalized);
  }
  return result;
}

function triggerArrayToText(value: string[]): string {
  return value.join('\n');
}

function triggerTextToArray(value: string): string[] {
  const unique = new Set<string>();
  const result: string[] = [];
  for (const chunk of value.split(/\r?\n|,/g)) {
    const normalized = chunk.trim();
    if (!normalized || unique.has(normalized.toLowerCase())) continue;
    unique.add(normalized.toLowerCase());
    result.push(normalized);
  }
  return result;
}

function messagesTextToArray(value: string): string[] {
  const result: string[] = [];
  for (const line of value.split(/\r?\n/g)) {
    const normalized = line.trim();
    if (!normalized) continue;
    result.push(normalized);
  }
  return result;
}

function clampPercent(value: number, min: number, max: number): number {
  if (!Number.isFinite(value)) return min;
  return Math.min(max, Math.max(min, Math.round(value)));
}

function numberOrFallback(value: unknown, fallback: number): number {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string' && value.trim() !== '') {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) return parsed;
  }
  return fallback;
}

function normalizeEngineScores(source: any): EngineRiskScores {
  return {
    toxicity: clampPercent(numberOrFallback(source?.toxicity, 0), 0, 100),
    threat: clampPercent(numberOrFallback(source?.threat, 0), 0, 100),
    scam: clampPercent(numberOrFallback(source?.scam, 0), 0, 100),
    recruitment: clampPercent(numberOrFallback(source?.recruitment, 0), 0, 100),
    drugs: clampPercent(numberOrFallback(source?.drugs, 0), 0, 100),
    terrorism: clampPercent(numberOrFallback(source?.terrorism, 0), 0, 100),
  };
}

// --- MAIN APP COMPONENT ---
function SentinelApp() {
  const { user, logout } = useAuth();
  const [activeTab, setActiveTab] = useState<ActiveTab>('dashboard');
  const [isRunning, setIsRunning] = useState(false);
  
  // Dashboard State
  const [messages, setMessages] = useState<any[]>([]);
  const [stats, setStats] = useState<Record<ThreatLabel, number>>({
    safe: 0,
    toxicity: 0,
    threat: 0,
    scam: 0,
    recruitment: 0,
    drugs: 0,
    terrorism: 0,
  });
  
  // Settings State
  const [settings, setSettings] = useState<SettingsState>(DEFAULT_SETTINGS);
  const [isSavingSettings, setIsSavingSettings] = useState(false);
  const [availableChatsByMode, setAvailableChatsByMode] = useState<Record<'bot' | 'user', AvailableTelegramChat[]>>({
    bot: [],
    user: [],
  });
  const [isLoadingAvailableChats, setIsLoadingAvailableChats] = useState(false);
  const [sessionPhoneNumber, setSessionPhoneNumber] = useState('');
  const [sessionRequestId, setSessionRequestId] = useState('');
  const [sessionCode, setSessionCode] = useState('');
  const [sessionPassword, setSessionPassword] = useState('');
  const [sessionNeedsPassword, setSessionNeedsPassword] = useState(false);
  const [isRequestingSessionCode, setIsRequestingSessionCode] = useState(false);
  const [isConfirmingSessionCode, setIsConfirmingSessionCode] = useState(false);
  const [cooldowns, setCooldowns] = useState<Record<CooldownKey, number>>({
    saveSettings: 0,
    syncChats: 0,
    sessionCode: 0,
    sessionConfirm: 0,
    engineControl: 0,
    engineTest: 0,
  });
  const [engineTestInput, setEngineTestInput] = useState('');
  const [engineTestResults, setEngineTestResults] = useState<EngineTestResult[]>([]);
  const [engineTestSummary, setEngineTestSummary] = useState<Record<ThreatLabel, number> | null>(null);
  const [isRunningEngineTest, setIsRunningEngineTest] = useState(false);
  const [engineTestUsedDefaultSet, setEngineTestUsedDefaultSet] = useState(false);
  const [engineTestPreset, setEngineTestPreset] = useState<EngineSelfTestPreset>('all');
  const [engineTestUsedPreset, setEngineTestUsedPreset] = useState<EngineSelfTestPreset | 'custom'>('all');
  const selectedModel = MODEL_OPTIONS.find((model) => model.id === settings.mlModel) ?? MODEL_OPTIONS[0];
  const selectedEnginePreset =
    ENGINE_SELF_TEST_PRESET_OPTIONS.find((preset) => preset.id === engineTestPreset) ??
    ENGINE_SELF_TEST_PRESET_OPTIONS[0];
  const lastUsedEnginePresetLabel =
    engineTestUsedPreset === 'custom'
      ? 'Custom messages'
      : (ENGINE_SELF_TEST_PRESET_OPTIONS.find((preset) => preset.id === engineTestUsedPreset)?.label ?? 'Unknown');
  const availableChats = availableChatsByMode[settings.authMode];

  // --- DATA FETCHING ---
  useEffect(() => {
    let interval: NodeJS.Timeout;
    
    const checkStatus = async () => {
      try {
        const res = await fetch('/api/status');
        if (!res.ok) {
          if (res.status === 401) logout();
          return;
        }
        const data = await res.json();
        setIsRunning(data.isRunning);
        
        if (data.isRunning) {
          const msgRes = await fetch('/api/messages');
          const msgData = await msgRes.json();
          setMessages(msgData);
          
          const statsRes = await fetch('/api/stats');
          const statsData = await statsRes.json();
          setStats((prev) => ({
            ...prev,
            safe: numberOrFallback(statsData?.safe, prev.safe),
            toxicity: numberOrFallback(statsData?.toxicity, prev.toxicity),
            threat: numberOrFallback(statsData?.threat, prev.threat),
            scam: numberOrFallback(statsData?.scam, prev.scam),
            recruitment: numberOrFallback(statsData?.recruitment, prev.recruitment),
            drugs: numberOrFallback(statsData?.drugs, prev.drugs),
            terrorism: numberOrFallback(statsData?.terrorism, prev.terrorism),
          }));
        }
      } catch (err) {
        console.error('Не удалось получить статус', err);
      }
    };

    checkStatus();
    interval = setInterval(checkStatus, 2000);
    
    return () => clearInterval(interval);
  }, [logout]);

  useEffect(() => {
    const timer = setInterval(() => {
      setCooldowns((prev) => {
        const next: Record<CooldownKey, number> = {
          saveSettings: Math.max(0, prev.saveSettings - 1),
          syncChats: Math.max(0, prev.syncChats - 1),
          sessionCode: Math.max(0, prev.sessionCode - 1),
          sessionConfirm: Math.max(0, prev.sessionConfirm - 1),
          engineControl: Math.max(0, prev.engineControl - 1),
          engineTest: Math.max(0, prev.engineTest - 1),
        };
        return next;
      });
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  const toPersistedSettingsPayload = (source: SettingsState) => ({
    apiId: source.apiId,
    apiHash: source.apiHash,
    authMode: source.authMode,
    botToken: source.botToken,
    sessionString: source.sessionString,
    sessionName: source.sessionName,
    userAuthAllMessages: source.userAuthAllMessages,
    botTargetChats: source.botTargetChats,
    userTargetChats: source.userTargetChats,
    targetChats: source.authMode === 'bot' ? source.botTargetChats : source.userTargetChats,
    proxyEnabled: source.proxyEnabled,
    proxyType: source.proxyType,
    proxyHost: source.proxyHost,
    proxyPort: source.proxyPort,
    proxyUser: source.proxyUser,
    proxyPass: source.proxyPass,
    downloadMedia: source.downloadMedia,
    mediaTypes: source.mediaTypes,
    keywords: source.keywords,
    scamTriggers: source.scamTriggers,
    drugTriggers: source.drugTriggers,
    recruitmentTriggers: source.recruitmentTriggers,
    terrorismTriggers: source.terrorismTriggers,
    threatTriggers: source.threatTriggers,
    toxicityTriggers: source.toxicityTriggers,
    mlModel: source.mlModel,
    threatThreshold: source.threatThreshold,
    categoryThresholds: source.categoryThresholds,
    enableHeuristics: source.enableHeuristics,
    enableCriticalPatterns: source.enableCriticalPatterns,
    modelWeight: source.modelWeight,
    heuristicWeight: source.heuristicWeight,
    modelTopK: source.modelTopK,
    maxAnalysisChars: source.maxAnalysisChars,
    urlScamBoost: source.urlScamBoost,
    keywordHitBoost: source.keywordHitBoost,
    criticalHitFloor: source.criticalHitFloor,
  });

  const toEngineSettingsPayload = (source: SettingsState) => ({
    keywords: source.keywords,
    scamTriggers: source.scamTriggers,
    drugTriggers: source.drugTriggers,
    recruitmentTriggers: source.recruitmentTriggers,
    terrorismTriggers: source.terrorismTriggers,
    threatTriggers: source.threatTriggers,
    toxicityTriggers: source.toxicityTriggers,
    mlModel: source.mlModel,
    threatThreshold: source.threatThreshold,
    categoryThresholds: source.categoryThresholds,
    enableHeuristics: source.enableHeuristics,
    enableCriticalPatterns: source.enableCriticalPatterns,
    modelWeight: source.modelWeight,
    heuristicWeight: source.heuristicWeight,
    modelTopK: source.modelTopK,
    maxAnalysisChars: source.maxAnalysisChars,
    urlScamBoost: source.urlScamBoost,
    keywordHitBoost: source.keywordHitBoost,
    criticalHitFloor: source.criticalHitFloor,
  });

  const startCooldown = (key: CooldownKey, seconds: number): void => {
    if (!Number.isFinite(seconds) || seconds <= 0) return;
    const wholeSeconds = Math.ceil(seconds);
    setCooldowns((prev) => ({
      ...prev,
      [key]: Math.max(prev[key], wholeSeconds),
    }));
  };

  const extractCooldownSeconds = (res: Response, payload: any): number => {
    if (res.status !== 429) return 0;
    const fromBodySec = typeof payload?.retryAfterSec === 'number' ? payload.retryAfterSec : 0;
    const fromBodyMs = typeof payload?.retryAfterMs === 'number' ? Math.ceil(payload.retryAfterMs / 1000) : 0;
    const fromHeader = Number(res.headers.get('Retry-After') ?? 0);
    return Math.max(0, fromBodySec, fromBodyMs, Number.isFinite(fromHeader) ? fromHeader : 0);
  };

  const cooldownText = (key: CooldownKey): string => {
    const seconds = cooldowns[key];
    return seconds > 0 ? `${seconds}s` : '';
  };

  const mergePersistedSettings = (prev: SettingsState, saved: any): SettingsState => {
    const authMode: 'bot' | 'user' =
      saved?.authMode === 'user' || saved?.authMode === 'bot' ? saved.authMode : prev.authMode;
    const fallbackBotTargetChats = resolveTargetChatsForMode(prev, 'bot', DEFAULT_SETTINGS.botTargetChats);
    const fallbackUserTargetChats = resolveTargetChatsForMode(prev, 'user', DEFAULT_SETTINGS.userTargetChats);
    const legacyTargetChats = toChatList(
      saved?.targetChats,
      authMode === 'bot' ? fallbackBotTargetChats : fallbackUserTargetChats
    );
    const botTargetChats = Array.isArray(saved?.botTargetChats)
      ? toChatList(saved.botTargetChats, fallbackBotTargetChats)
      : authMode === 'bot'
        ? legacyTargetChats
        : fallbackBotTargetChats;
    const userTargetChats = Array.isArray(saved?.userTargetChats)
      ? toChatList(saved.userTargetChats, fallbackUserTargetChats)
      : authMode === 'user'
        ? legacyTargetChats
        : fallbackUserTargetChats;

    return {
      ...prev,
      ...saved,
      authMode,
      sessionString: typeof saved?.sessionString === 'string' ? saved.sessionString : prev.sessionString,
      userAuthAllMessages: typeof saved?.userAuthAllMessages === 'boolean'
        ? saved.userAuthAllMessages
        : prev.userAuthAllMessages,
      botTargetChats,
      userTargetChats,
      targetChats: authMode === 'bot' ? botTargetChats : userTargetChats,
      keywords: normalizeTriggerArray(saved?.keywords, prev.keywords),
      scamTriggers: normalizeTriggerArray(saved?.scamTriggers, prev.scamTriggers),
      drugTriggers: normalizeTriggerArray(saved?.drugTriggers, prev.drugTriggers),
      recruitmentTriggers: normalizeTriggerArray(saved?.recruitmentTriggers, prev.recruitmentTriggers),
      terrorismTriggers: normalizeTriggerArray(saved?.terrorismTriggers, prev.terrorismTriggers),
      threatTriggers: normalizeTriggerArray(saved?.threatTriggers, prev.threatTriggers),
      toxicityTriggers: normalizeTriggerArray(saved?.toxicityTriggers, prev.toxicityTriggers),
      categoryThresholds: {
        toxicity: clampPercent(numberOrFallback(saved?.categoryThresholds?.toxicity, prev.categoryThresholds.toxicity), 1, 99),
        threat: clampPercent(numberOrFallback(saved?.categoryThresholds?.threat, prev.categoryThresholds.threat), 1, 99),
        scam: clampPercent(numberOrFallback(saved?.categoryThresholds?.scam, prev.categoryThresholds.scam), 1, 99),
        recruitment: clampPercent(numberOrFallback(saved?.categoryThresholds?.recruitment, prev.categoryThresholds.recruitment), 1, 99),
        drugs: clampPercent(numberOrFallback(saved?.categoryThresholds?.drugs, prev.categoryThresholds.drugs), 1, 99),
        terrorism: clampPercent(numberOrFallback(saved?.categoryThresholds?.terrorism, prev.categoryThresholds.terrorism), 1, 99),
      },
      enableHeuristics: typeof saved?.enableHeuristics === 'boolean' ? saved.enableHeuristics : prev.enableHeuristics,
      enableCriticalPatterns: typeof saved?.enableCriticalPatterns === 'boolean' ? saved.enableCriticalPatterns : prev.enableCriticalPatterns,
      modelWeight: clampPercent(numberOrFallback(saved?.modelWeight, prev.modelWeight), 0, 100),
      heuristicWeight: clampPercent(numberOrFallback(saved?.heuristicWeight, prev.heuristicWeight), 0, 100),
      modelTopK: clampPercent(numberOrFallback(saved?.modelTopK, prev.modelTopK), 1, 30),
      maxAnalysisChars: clampPercent(numberOrFallback(saved?.maxAnalysisChars, prev.maxAnalysisChars), 200, 4000),
      urlScamBoost: clampPercent(numberOrFallback(saved?.urlScamBoost, prev.urlScamBoost), 0, 100),
      keywordHitBoost: clampPercent(numberOrFallback(saved?.keywordHitBoost, prev.keywordHitBoost), 0, 100),
      criticalHitFloor: clampPercent(numberOrFallback(saved?.criticalHitFloor, prev.criticalHitFloor), 0, 100),
      mediaTypes: {
        ...prev.mediaTypes,
        ...(saved?.mediaTypes ?? {}),
      },
      newChatInput: '',
      newKeywordInput: '',
    };
  };

  const loadAvailableChats = async (
    credentials?: Partial<Pick<SettingsState, 'apiId' | 'apiHash' | 'authMode' | 'botToken' | 'sessionString'>>,
    showNotification = true
  ): Promise<void> => {
    if (!user || user.role !== 'admin') return;
    if (cooldowns.syncChats > 0) {
      if (showNotification) {
        alert(`Chat sync cooldown: ${cooldownText('syncChats')}`);
      }
      return;
    }

    const apiId = (credentials?.apiId ?? settings.apiId).trim();
    const apiHash = (credentials?.apiHash ?? settings.apiHash).trim();
    const authMode = credentials?.authMode ?? settings.authMode;
    const botToken = (credentials?.botToken ?? settings.botToken).trim();
    const sessionString = (credentials?.sessionString ?? settings.sessionString).trim();

    if (!apiId || !apiHash) {
      if (showNotification) {
        alert('Fill API ID and API Hash first.');
      }
      return;
    }

    if (authMode === 'bot' && !botToken) {
      if (showNotification) {
        alert('Fill Bot Token first.');
      }
      return;
    }

    if (authMode === 'user' && !sessionString) {
      if (showNotification) {
        alert('Fill Session String first.');
      }
      return;
    }

    setIsLoadingAvailableChats(true);
    try {
      const res = await fetch('/api/telegram/chats', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ apiId, apiHash, authMode, botToken, sessionString }),
      });

      const data = await res.json();
      if (!res.ok) {
        const cooldownSeconds = extractCooldownSeconds(res, data);
        if (cooldownSeconds > 0) {
          startCooldown('syncChats', cooldownSeconds);
        }
        throw new Error(data?.error ?? 'Failed to load Telegram chats');
      }

      const chats: AvailableTelegramChat[] = Array.isArray(data?.chats)
        ? data.chats
            .filter((item: any) => item && typeof item.id === 'string')
            .map((item: any) => ({
              id: String(item.id),
              title: typeof item.title === 'string' && item.title.trim().length > 0 ? item.title.trim() : 'Unknown Chat',
              username: typeof item.username === 'string' && item.username.trim().length > 0 ? item.username.trim() : null,
              type:
                item.type === 'group' || item.type === 'supergroup' || item.type === 'channel'
                  ? item.type
                  : 'group',
              avatar: typeof item.avatar === 'string' && item.avatar.length > 0 ? item.avatar : null,
            }))
        : [];

      setAvailableChatsByMode((prev) => ({
        ...prev,
        [authMode]: chats,
      }));
    } catch (err) {
      console.error('Failed to load available Telegram chats', err);
      if (showNotification) {
        alert(`Failed to load Telegram chats: ${(err as Error).message}`);
      }
    } finally {
      setIsLoadingAvailableChats(false);
    }
  };

  const requestSessionCode = async (): Promise<void> => {
    if (cooldowns.sessionCode > 0) {
      alert(`Code request cooldown: ${cooldownText('sessionCode')}`);
      return;
    }

    const apiId = settings.apiId.trim();
    const apiHash = settings.apiHash.trim();
    const phoneNumber = sessionPhoneNumber.trim();

    if (!apiId || !apiHash || !phoneNumber) {
      alert('Fill API ID, API Hash and phone number first.');
      return;
    }

    setIsRequestingSessionCode(true);
    try {
      const res = await fetch('/api/session/request-code', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ apiId, apiHash, phoneNumber }),
      });

      const data = await res.json();
      if (!res.ok) {
        const cooldownSeconds = extractCooldownSeconds(res, data);
        if (cooldownSeconds > 0) {
          startCooldown('sessionCode', cooldownSeconds);
        }
        throw new Error(data?.error ?? 'Failed to request login code');
      }

      setSessionRequestId(String(data.requestId ?? ''));
      setSessionCode('');
      setSessionPassword('');
      setSessionNeedsPassword(false);
      alert('Code requested. Enter Telegram login code.');
    } catch (err) {
      console.error('Failed to request session code', err);
      alert(`Failed to request code: ${(err as Error).message}`);
    } finally {
      setIsRequestingSessionCode(false);
    }
  };

  const confirmSessionCode = async (): Promise<void> => {
    if (cooldowns.sessionConfirm > 0) {
      alert(`Session confirm cooldown: ${cooldownText('sessionConfirm')}`);
      return;
    }

    const requestId = sessionRequestId.trim();
    const code = sessionCode.trim();

    if (!requestId) {
      alert('Request code first.');
      return;
    }
    if (!code) {
      alert('Enter the Telegram code.');
      return;
    }

    setIsConfirmingSessionCode(true);
    try {
      const res = await fetch('/api/session/complete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          requestId,
          code,
          password: sessionPassword.trim(),
        }),
      });

      const data = await res.json();
      if (res.status === 429) {
        const cooldownSeconds = extractCooldownSeconds(res, data);
        if (cooldownSeconds > 0) {
          startCooldown('sessionConfirm', cooldownSeconds);
        }
      }
      if (res.status === 409 && data?.requiresPassword) {
        setSessionNeedsPassword(true);
        alert('This account has 2FA password. Enter it and confirm again.');
        return;
      }
      if (!res.ok) {
        throw new Error(data?.error ?? 'Failed to complete authorization');
      }

      const generated = typeof data?.sessionString === 'string' ? data.sessionString : '';
      if (!generated) {
        throw new Error('Empty session string returned');
      }

      setSettings((prev) => ({ ...prev, sessionString: generated }));
      setSessionRequestId('');
      setSessionCode('');
      setSessionPassword('');
      setSessionNeedsPassword(false);
      alert('Session string generated and inserted into settings.');
    } catch (err) {
      console.error('Failed to confirm session code', err);
      alert(`Failed to complete auth: ${(err as Error).message}`);
    } finally {
      setIsConfirmingSessionCode(false);
    }
  };

  useEffect(() => {
    if (!user || user.role !== 'admin') return;
    let cancelled = false;

    const loadSettings = async () => {
      try {
        const res = await fetch('/api/settings');
        if (!res.ok) return;

        const saved = await res.json();
        if (cancelled) return;

        setSettings((prev) => mergePersistedSettings(prev, saved));

      } catch (err) {
        console.error('Failed to load saved settings', err);
      }
    };

    loadSettings();
    return () => {
      cancelled = true;
    };
  }, [user]);

  useEffect(() => {
    setSessionRequestId('');
    setSessionCode('');
    setSessionPassword('');
    setSessionNeedsPassword(false);
  }, [settings.authMode]);

  const saveSettings = async (showNotification = true): Promise<boolean> => {
    if (!user || user.role !== 'admin') return false;
    if (cooldowns.saveSettings > 0) {
      if (showNotification) {
        alert(`Save cooldown: ${cooldownText('saveSettings')}`);
      }
      return false;
    }
    setIsSavingSettings(true);

    try {
      const res = await fetch('/api/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(toPersistedSettingsPayload(settings)),
      });

      const data = await res.json();
      if (!res.ok) {
        const cooldownSeconds = extractCooldownSeconds(res, data);
        if (cooldownSeconds > 0) {
          startCooldown('saveSettings', cooldownSeconds);
        }
        if (showNotification) {
          alert(data.error ?? 'Не удалось сохранить конфигурацию');
        }
        return false;
      }

      if (data?.settings) {
        setSettings((prev) => mergePersistedSettings(prev, data.settings));
      }

      if (showNotification) {
        alert('Конфигурация сохранена');
      }

      return true;
    } catch (err) {
      console.error('Failed to save settings', err);
      if (showNotification) {
        alert('Ошибка сети при сохранении конфигурации');
      }
      return false;
    } finally {
      setIsSavingSettings(false);
    }
  };

  const toggleEngine = async () => {
    if (!user || user.role !== 'admin') return;
    if (cooldowns.engineControl > 0) {
      alert(`Engine control cooldown: ${cooldownText('engineControl')}`);
      return;
    }
    try {
      if (isRunning) {
        const stopRes = await fetch('/api/stop', { method: 'POST' });
        const stopData = await stopRes.json();
        if (!stopRes.ok) {
          const cooldownSeconds = extractCooldownSeconds(stopRes, stopData);
          if (cooldownSeconds > 0) {
            startCooldown('engineControl', cooldownSeconds);
          }
          alert(stopData?.error ?? 'Failed to stop engine');
          return;
        }
        setIsRunning(false);
      } else {
        const saved = await saveSettings(false);
        if (!saved) {
          alert('Сначала сохраните настройки и попробуйте снова');
          return;
        }

        const res = await fetch('/api/start', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            apiId: settings.apiId,
            apiHash: settings.apiHash,
            authMode: settings.authMode,
            botToken: settings.botToken,
            sessionString: settings.sessionString,
            userAuthAllMessages: settings.userAuthAllMessages,
            chats: settings.targetChats,
            model: settings.mlModel,
            threatThreshold: settings.threatThreshold / 100
          })
        });
        const data = await res.json();
        if (!res.ok) {
          const cooldownSeconds = extractCooldownSeconds(res, data);
          if (cooldownSeconds > 0) {
            startCooldown('engineControl', cooldownSeconds);
          }
          alert(`ÐžÑˆÐ¸Ð±ÐºÐ° Ð·Ð°Ð¿ÑƒÑÐºÐ° Ð´Ð²Ð¸Ð¶ÐºÐ°: ${data?.error ?? 'Unknown error'}`);
          return;
        }
        if (data.error) {
          alert(`Ошибка запуска движка: ${data.error}`);
        } else {
          setIsRunning(true);
        }
      }
    } catch (err) {
      console.error('Failed to toggle engine', err);
      alert('Сетевая ошибка при переключении движка');
    }
  };

  const runEngineSelfTest = async (): Promise<void> => {
    if (!user || user.role !== 'admin') return;
    if (cooldowns.engineTest > 0) {
      alert(`Engine test cooldown: ${cooldownText('engineTest')}`);
      return;
    }

    const customMessages = messagesTextToArray(engineTestInput).slice(0, 80);
    setIsRunningEngineTest(true);

    try {
      const res = await fetch('/api/engine/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          settings: toEngineSettingsPayload(settings),
          messages: customMessages,
          preset: engineTestPreset,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        const cooldownSeconds = extractCooldownSeconds(res, data);
        if (cooldownSeconds > 0) {
          startCooldown('engineTest', cooldownSeconds);
        }
        throw new Error(data?.error ?? 'Engine self-test failed');
      }

      const results: EngineTestResult[] = Array.isArray(data?.results)
        ? data.results
            .filter((item: any) => item && typeof item.text === 'string')
            .map((item: any) => ({
              text: item.text,
              expected: typeof item.expected === 'string' ? item.expected : null,
              scenario: typeof item.scenario === 'string' ? item.scenario : 'custom',
              type:
                item.type === 'safe' ||
                item.type === 'toxicity' ||
                item.type === 'threat' ||
                item.type === 'scam' ||
                item.type === 'recruitment' ||
                item.type === 'drugs' ||
                item.type === 'terrorism'
                  ? item.type
                  : 'safe',
              confidence: clampPercent(numberOrFallback(item.confidence, 0), 0, 100),
              scores: normalizeEngineScores(item?.scores),
              heuristicScores: normalizeEngineScores(item?.heuristicScores),
              modelScores: normalizeEngineScores(item?.modelScores),
              thresholds: normalizeEngineScores(item?.thresholds),
            }))
        : [];

      setEngineTestResults(results);
      setEngineTestSummary(
        data?.summary && typeof data.summary === 'object'
          ? {
              safe: clampPercent(numberOrFallback((data.summary as any).safe, 0), 0, 10000),
              toxicity: clampPercent(numberOrFallback((data.summary as any).toxicity, 0), 0, 10000),
              threat: clampPercent(numberOrFallback((data.summary as any).threat, 0), 0, 10000),
              scam: clampPercent(numberOrFallback((data.summary as any).scam, 0), 0, 10000),
              recruitment: clampPercent(numberOrFallback((data.summary as any).recruitment, 0), 0, 10000),
              drugs: clampPercent(numberOrFallback((data.summary as any).drugs, 0), 0, 10000),
              terrorism: clampPercent(numberOrFallback((data.summary as any).terrorism, 0), 0, 10000),
            }
          : null
      );
      setEngineTestUsedDefaultSet(Boolean(data?.usedDefaultDataset));
      const usedPresetRaw = typeof data?.usedPreset === 'string' ? data.usedPreset : '';
      const normalizedUsedPreset: EngineSelfTestPreset | 'custom' =
        usedPresetRaw === 'custom' ||
        usedPresetRaw === 'all' ||
        usedPresetRaw === 'recruitment' ||
        usedPresetRaw === 'drugs' ||
        usedPresetRaw === 'terrorism'
          ? usedPresetRaw
          : customMessages.length > 0
            ? 'custom'
            : engineTestPreset;
      setEngineTestUsedPreset(normalizedUsedPreset);
    } catch (error) {
      console.error('Failed to run engine self-test', error);
      alert(`Engine self-test failed: ${(error as Error).message}`);
    } finally {
      setIsRunningEngineTest(false);
    }
  };

  // --- HANDLERS ---
  const handleAddChat = () => {
    const normalizedChat = settings.newChatInput.trim();
    if (!normalizedChat) return;

    setSettings((prev) => {
      const activeChats = prev.authMode === 'bot' ? prev.botTargetChats : prev.userTargetChats;
      const nextChats = activeChats.includes(normalizedChat) ? activeChats : [...activeChats, normalizedChat];
      if (prev.authMode === 'bot') {
        return { ...prev, botTargetChats: nextChats, targetChats: nextChats, newChatInput: '' };
      }
      return { ...prev, userTargetChats: nextChats, targetChats: nextChats, newChatInput: '' };
    });
  };

  const handleRemoveChat = (chat: string) => {
    setSettings((prev) => {
      const activeChats = prev.authMode === 'bot' ? prev.botTargetChats : prev.userTargetChats;
      const nextChats = activeChats.filter((c) => c !== chat);
      if (prev.authMode === 'bot') {
        return { ...prev, botTargetChats: nextChats, targetChats: nextChats };
      }
      return { ...prev, userTargetChats: nextChats, targetChats: nextChats };
    });
  };

  const handleToggleAvailableChat = (chatId: string) => {
    setSettings((prev) => {
      const activeChats = prev.authMode === 'bot' ? prev.botTargetChats : prev.userTargetChats;
      const isSelected = activeChats.includes(chatId);
      const nextChats = isSelected
        ? activeChats.filter((chat) => chat !== chatId)
        : [...activeChats, chatId];
      if (prev.authMode === 'bot') {
        return { ...prev, botTargetChats: nextChats, targetChats: nextChats };
      }
      return { ...prev, userTargetChats: nextChats, targetChats: nextChats };
    });
  };

  const handleSelectAllAvailableChats = () => {
    if (availableChats.length === 0) return;
    setSettings((prev) => {
      const activeChats = prev.authMode === 'bot' ? prev.botTargetChats : prev.userTargetChats;
      const mergedChats = Array.from(new Set([...activeChats, ...availableChats.map((chat) => chat.id)]));
      if (prev.authMode === 'bot') {
        return { ...prev, botTargetChats: mergedChats, targetChats: mergedChats };
      }
      return { ...prev, userTargetChats: mergedChats, targetChats: mergedChats };
    });
  };

  const handleClearAvailableChats = () => {
    if (availableChats.length === 0) return;
    const availableIds = new Set(availableChats.map((chat) => chat.id));
    setSettings((prev) => {
      const activeChats = prev.authMode === 'bot' ? prev.botTargetChats : prev.userTargetChats;
      const nextChats = activeChats.filter((chatId) => !availableIds.has(chatId));
      if (prev.authMode === 'bot') {
        return { ...prev, botTargetChats: nextChats, targetChats: nextChats };
      }
      return { ...prev, userTargetChats: nextChats, targetChats: nextChats };
    });
  };

  const handleAddKeyword = () => {
    if (settings.newKeywordInput && !settings.keywords.includes(settings.newKeywordInput)) {
      setSettings(s => ({ ...s, keywords: [...s.keywords, s.newKeywordInput], newKeywordInput: '' }));
    }
  };

  const handleRemoveKeyword = (kw: string) => {
    setSettings(s => ({ ...s, keywords: s.keywords.filter(k => k !== kw) }));
  };

  const availableChatIds = new Set(availableChats.map((chat) => chat.id));
  const manualTargetChats = settings.targetChats.filter((chatId) => !availableChatIds.has(chatId));
  const selectedAvailableCount = availableChats.reduce(
    (count, chat) => (settings.targetChats.includes(chat.id) ? count + 1 : count),
    0
  );
  const allAvailableSelected = availableChats.length > 0 && selectedAvailableCount === availableChats.length;

  // --- RENDERERS ---
  const renderDashboard = () => {
        const pieData = Object.entries(stats).map(([name, value]) => ({ name, value }));
    const totalMessages: number =
      stats.safe +
      stats.toxicity +
      stats.threat +
      stats.scam +
      stats.recruitment +
      stats.drugs +
      stats.terrorism;
    const sumThreats: number =
      stats.toxicity +
      stats.threat +
      stats.scam +
      stats.recruitment +
      stats.drugs +
      stats.terrorism;
    const threatRatio: string = totalMessages === 0 ? "0.0" : ((sumThreats / totalMessages) * 100).toFixed(1);

    return (
      <div className="space-y-6 animate-in fade-in duration-300">
        {/* Metrics Row */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-[#111113] border border-slate-800 rounded-xl p-5 shadow-sm">
            <div className="flex items-center justify-between mb-2">
              <span className="text-slate-400 text-sm font-medium">Всего проанализировано</span>
              <Activity className="w-4 h-4 text-indigo-400" />
            </div>
            <div className="text-3xl font-light text-slate-100">{totalMessages}</div>
          </div>
          <div className="bg-[#111113] border border-slate-800 rounded-xl p-5 shadow-sm">
            <div className="flex items-center justify-between mb-2">
              <span className="text-slate-400 text-sm font-medium">Коэффициент угроз</span>
              <AlertTriangle className="w-4 h-4 text-amber-400" />
            </div>
            <div className="text-3xl font-light text-slate-100">{threatRatio}%</div>
          </div>
          <div className="bg-[#111113] border border-slate-800 rounded-xl p-5 shadow-sm">
            <div className="flex items-center justify-between mb-2">
              <span className="text-slate-400 text-sm font-medium">Активные цели</span>
              <Globe className="w-4 h-4 text-emerald-400" />
            </div>
            <div className="text-3xl font-light text-slate-100">{settings.targetChats.length}</div>
          </div>
          <div className="bg-[#111113] border border-slate-800 rounded-xl p-5 shadow-sm">
            <div className="flex items-center justify-between mb-2">
              <span className="text-slate-400 text-sm font-medium">ML-модель</span>
              <Cpu className="w-4 h-4 text-violet-400" />
            </div>
            <div className="text-sm font-mono text-slate-300 mt-2 truncate" title={selectedModel.name}>
              {selectedModel.name}
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Live Feed */}
          <div className="lg:col-span-2 bg-[#111113] border border-slate-800 rounded-xl flex flex-col h-[500px] shadow-sm overflow-hidden">
            <div className="px-5 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-900/20">
              <h3 className="text-sm font-semibold text-slate-200 flex items-center">
                <Terminal className="w-4 h-4 mr-2 text-indigo-400" /> Лента перехвата в реальном времени
              </h3>
              {isRunning && (
                <span className="flex items-center text-xs text-emerald-400 font-mono">
                  <span className="w-2 h-2 rounded-full bg-emerald-400 mr-2 animate-pulse"></span>
                  ПРОСЛУШИВАЕТСЯ
                </span>
              )}
            </div>
            <div className="flex-1 overflow-y-auto p-2 custom-scrollbar">
              {messages.length === 0 ? (
                <div className="h-full flex items-center justify-center text-slate-500 text-sm font-mono">
                  Ожидание входящих сообщений...
                </div>
              ) : (
                <div className="space-y-1">
                  {messages.map(msg => (
                    <div key={msg.id} className="group flex flex-col p-3 hover:bg-slate-800/30 rounded-lg transition-colors border border-transparent hover:border-slate-800/50">
                      <div className="flex items-center justify-between mb-1.5">
                        <div className="flex items-center space-x-2 text-xs font-mono text-slate-400">
                          <span className="text-slate-500">{msg.time}</span>
                          <span className="text-indigo-400">{msg.chat}</span>
                          <span className="text-slate-500">→</span>
                          <span className="text-slate-300">{msg.sender}</span>
                        </div>
                        <div className="flex items-center space-x-2">
                          <span className="text-[10px] font-mono text-slate-500">УВЕРЕННОСТЬ: {(msg.score * 100).toFixed(0)}%</span>
                          <span className={cn(
                            "text-[10px] uppercase tracking-wider px-2 py-0.5 rounded-full font-semibold",
                            msg.type === 'safe' ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20" :
                            msg.type === 'toxicity' ? "bg-amber-500/10 text-amber-400 border border-amber-500/20" :
                            msg.type === 'threat' ? "bg-red-500/10 text-red-400 border border-red-500/20" :
                            msg.type === 'recruitment' ? "bg-sky-500/10 text-sky-400 border border-sky-500/20" :
                            msg.type === 'drugs' ? "bg-yellow-500/10 text-yellow-400 border border-yellow-500/20" :
                            msg.type === 'terrorism' ? "bg-rose-500/10 text-rose-400 border border-rose-500/20" :
                            "bg-violet-500/10 text-violet-400 border border-violet-500/20"
                          )}>
                            {msg.type}
                          </span>
                        </div>
                      </div>
                      {(() => {
                        const text = typeof msg.text === 'string' ? msg.text : '';
                        const normalizedText = text.trim().length > 0 ? text : '[No text content]';
                        const showSpoiler = normalizedText.length > 220 || normalizedText.includes('\n');

                        if (!showSpoiler) {
                          return <p className="text-sm text-slate-300 leading-relaxed break-words">{normalizedText}</p>;
                        }

                        return (
                          <details className="text-sm">
                            <summary className="cursor-pointer select-none text-slate-400 hover:text-slate-200 transition-colors">
                              Show full message ({normalizedText.length} chars)
                            </summary>
                            <pre className="mt-2 whitespace-pre-wrap break-words text-slate-300 font-sans leading-relaxed">
                              {normalizedText}
                            </pre>
                          </details>
                        );
                      })()}
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Charts */}
          <div className="bg-[#111113] border border-slate-800 rounded-xl flex flex-col h-[500px] shadow-sm overflow-hidden">
            <div className="px-5 py-4 border-b border-slate-800 bg-slate-900/20">
              <h3 className="text-sm font-semibold text-slate-200 flex items-center">
                <PieChart className="w-4 h-4 mr-2 text-indigo-400" /> Распределение угроз
              </h3>
            </div>
            <div className="flex-1 p-4 flex items-center justify-center">
              {totalMessages === 0 ? (
                <div className="text-slate-500 text-sm font-mono">Нет данных для отображения</div>
              ) : (
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={pieData}
                      cx="50%"
                      cy="50%"
                      innerRadius={60}
                      outerRadius={80}
                      paddingAngle={5}
                      dataKey="value"
                      stroke="none"
                    >
                      {pieData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={THREAT_COLORS[entry.name as keyof typeof THREAT_COLORS]} />
                      ))}
                    </Pie>
                    <RechartsTooltip 
                      contentStyle={{ backgroundColor: '#111113', borderColor: '#1F2937', color: '#f1f5f9', borderRadius: '8px' }}
                      itemStyle={{ color: '#f1f5f9' }}
                    />
                    <Legend verticalAlign="bottom" height={36} iconType="circle" />
                  </PieChart>
                </ResponsiveContainer>
              )}
            </div>
          </div>
        </div>
      </div>
    );
  };

  const renderSettings = (section: 'agents' | 'engine' | 'proxy') => {
    if (user.role !== 'admin') return null;
    return (
      <div className="space-y-6 animate-in fade-in duration-300 max-w-5xl mx-auto pb-12">
        
        {section === 'agents' && (
          <>
        {/* Section 1: Authentication */}
        <div className="bg-[#111113] border border-slate-800 rounded-xl shadow-sm overflow-hidden">
          <div className="px-6 py-4 border-b border-slate-800 bg-slate-900/30 flex items-center">
            <Lock className="w-5 h-5 mr-3 text-indigo-400" />
            <h2 className="text-base font-semibold text-slate-200">Аутентификация Telegram</h2>
          </div>
          <div className="p-6 grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="space-y-2">
              <label className="text-xs font-medium text-slate-400 uppercase tracking-wider">API ID (my.telegram.org)</label>
              <input 
                type="text" 
                value={settings.apiId}
                onChange={e => setSettings({...settings, apiId: e.target.value})}
                className="w-full bg-[#0A0A0B] border border-slate-700 rounded-lg px-4 py-2.5 text-sm text-slate-200 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all font-mono"
                placeholder="например, 1234567"
              />
            </div>
            <div className="space-y-2">
              <label className="text-xs font-medium text-slate-400 uppercase tracking-wider">API-хеш</label>
              <input 
                type="password" 
                value={settings.apiHash}
                onChange={e => setSettings({...settings, apiHash: e.target.value})}
                className="w-full bg-[#0A0A0B] border border-slate-700 rounded-lg px-4 py-2.5 text-sm text-slate-200 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all font-mono"
                placeholder="••••••••••••••••"
              />
            </div>
            <div className="space-y-2">
              <label className="text-xs font-medium text-slate-400 uppercase tracking-wider">Auth Mode</label>
              <select
                value={settings.authMode}
                onChange={e => {
                  const nextMode = e.target.value as 'bot' | 'user';
                  setSettings((prev) => ({
                    ...prev,
                    authMode: nextMode,
                    targetChats: [...(nextMode === 'bot' ? prev.botTargetChats : prev.userTargetChats)],
                  }));
                }}
                className="w-full bg-[#0A0A0B] border border-slate-700 rounded-lg px-4 py-2.5 text-sm text-slate-200 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all"
              >
                <option value="bot">Bot Token</option>
                <option value="user">Telegram Account Session</option>
              </select>
            </div>
            {settings.authMode === 'bot' ? (
              <div className="space-y-2">
                <label className="text-xs font-medium text-slate-400 uppercase tracking-wider">Bot Token</label>
                <input
                  type="password"
                  value={settings.botToken}
                  onChange={e => setSettings({...settings, botToken: e.target.value})}
                  className="w-full bg-[#0A0A0B] border border-slate-700 rounded-lg px-4 py-2.5 text-sm text-slate-200 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all font-mono"
                  placeholder="123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11"
                />
                <p className="text-[11px] text-amber-500 mt-1">Bot mode reads only chats where the bot is added.</p>
              </div>
            ) : (
              <div className="space-y-3">
                <label className="text-xs font-medium text-slate-400 uppercase tracking-wider">Session String</label>
                <textarea
                  value={settings.sessionString}
                  onChange={e => setSettings({...settings, sessionString: e.target.value})}
                  rows={3}
                  className="w-full bg-[#0A0A0B] border border-slate-700 rounded-lg px-4 py-2.5 text-sm text-slate-200 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all font-mono"
                  placeholder="Paste Telegram String Session for your account"
                />
                <p className="text-[11px] text-amber-500 mt-1">Account mode uses your Telegram account dialogs directly.</p>

                <div className="pt-2 border-t border-slate-800 space-y-2">
                  <label className="text-xs font-medium text-slate-400 uppercase tracking-wider">Generate In Panel</label>
                  <input
                    type="text"
                    value={sessionPhoneNumber}
                    onChange={e => setSessionPhoneNumber(e.target.value)}
                    className="w-full bg-[#0A0A0B] border border-slate-700 rounded-lg px-4 py-2.5 text-sm text-slate-200 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all font-mono"
                    placeholder="+79991234567"
                  />
                  <button
                    type="button"
                    onClick={() => void requestSessionCode()}
                    disabled={isRequestingSessionCode || cooldowns.sessionCode > 0}
                    className={cn(
                      "w-full px-3 py-2 rounded-lg border text-sm transition-colors",
                      isRequestingSessionCode || cooldowns.sessionCode > 0
                        ? "border-slate-700 text-slate-500 cursor-not-allowed"
                        : "border-indigo-500/20 text-indigo-300 hover:bg-indigo-500/10"
                    )}
                  >
                    {isRequestingSessionCode
                      ? 'Requesting code...'
                      : cooldowns.sessionCode > 0
                        ? `Cooldown ${cooldownText('sessionCode')}`
                        : 'Send Telegram Code'}
                  </button>

                  {sessionRequestId && (
                    <div className="space-y-2 pt-2">
                      <input
                        type="text"
                        value={sessionCode}
                        onChange={e => setSessionCode(e.target.value)}
                        className="w-full bg-[#0A0A0B] border border-slate-700 rounded-lg px-4 py-2.5 text-sm text-slate-200 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all font-mono"
                        placeholder="Code from Telegram"
                      />
                      <input
                        type="password"
                        value={sessionPassword}
                        onChange={e => setSessionPassword(e.target.value)}
                        className="w-full bg-[#0A0A0B] border border-slate-700 rounded-lg px-4 py-2.5 text-sm text-slate-200 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all font-mono"
                        placeholder={sessionNeedsPassword ? '2FA password (required)' : '2FA password (if enabled)'}
                      />
                      <button
                        type="button"
                        onClick={() => void confirmSessionCode()}
                        disabled={isConfirmingSessionCode || cooldowns.sessionConfirm > 0}
                        className={cn(
                          "w-full px-3 py-2 rounded-lg border text-sm transition-colors",
                          isConfirmingSessionCode || cooldowns.sessionConfirm > 0
                            ? "border-slate-700 text-slate-500 cursor-not-allowed"
                            : "border-emerald-500/20 text-emerald-300 hover:bg-emerald-500/10"
                        )}
                      >
                        {isConfirmingSessionCode
                          ? 'Confirming...'
                          : cooldowns.sessionConfirm > 0
                            ? `Cooldown ${cooldownText('sessionConfirm')}`
                            : 'Confirm And Generate Session'}
                      </button>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>
          </>
        )}

        {(section === 'agents' || section === 'engine') && (
          <div className={cn("grid gap-6", section === 'agents' ? "grid-cols-1 lg:grid-cols-2" : "grid-cols-1")}>
          {section === 'agents' && (
          <div className="bg-[#111113] border border-slate-800 rounded-xl shadow-sm overflow-hidden flex flex-col">
            <div className="px-6 py-4 border-b border-slate-800 bg-slate-900/30 flex items-center">
              <Globe className="w-5 h-5 mr-3 text-emerald-400" />
              <h2 className="text-base font-semibold text-slate-200">Целевые чаты и каналы</h2>
            </div>
            <div className="p-6 flex-1 flex flex-col space-y-4">
              <div className="flex items-center justify-between gap-3">
                <p className="text-xs text-slate-400 leading-relaxed">
                  Sync groups/channels for current auth mode and select targets.
                </p>
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={handleSelectAllAvailableChats}
                    disabled={isLoadingAvailableChats || availableChats.length === 0 || allAvailableSelected}
                    className={cn(
                      "inline-flex items-center gap-2 px-3 py-2 rounded-lg border text-xs font-medium transition-colors",
                      isLoadingAvailableChats || availableChats.length === 0 || allAvailableSelected
                        ? "border-slate-700 text-slate-500 cursor-not-allowed"
                        : "border-sky-500/20 text-sky-300 hover:bg-sky-500/10"
                    )}
                  >
                    Select All
                  </button>
                  <button
                    type="button"
                    onClick={handleClearAvailableChats}
                    disabled={isLoadingAvailableChats || selectedAvailableCount === 0}
                    className={cn(
                      "inline-flex items-center gap-2 px-3 py-2 rounded-lg border text-xs font-medium transition-colors",
                      isLoadingAvailableChats || selectedAvailableCount === 0
                        ? "border-slate-700 text-slate-500 cursor-not-allowed"
                        : "border-rose-500/20 text-rose-300 hover:bg-rose-500/10"
                    )}
                  >
                    Clear
                  </button>
                  <button
                    type="button"
                    onClick={() => void loadAvailableChats(undefined, true)}
                    disabled={isLoadingAvailableChats || cooldowns.syncChats > 0}
                    className={cn(
                      "inline-flex items-center gap-2 px-3 py-2 rounded-lg border text-xs font-medium transition-colors",
                      isLoadingAvailableChats || cooldowns.syncChats > 0
                        ? "border-slate-700 text-slate-500 cursor-not-allowed"
                        : "border-emerald-500/20 text-emerald-400 hover:bg-emerald-500/10"
                    )}
                  >
                    <RefreshCw className={cn("w-4 h-4", isLoadingAvailableChats && "animate-spin")} />
                    {isLoadingAvailableChats
                      ? 'Syncing...'
                      : cooldowns.syncChats > 0
                        ? `Cooldown ${cooldownText('syncChats')}`
                        : 'Sync list'}
                  </button>
                </div>
              </div>

              {settings.authMode === 'user' && (
                <div className="rounded-lg border border-slate-700 bg-slate-900/40 px-3 py-2">
                  <label className="flex items-center justify-between gap-3 cursor-pointer">
                    <div>
                      <div className="text-xs font-medium text-slate-200">Process all incoming messages</div>
                      <div className="text-[11px] text-slate-400 mt-0.5">
                        When enabled, account mode ignores target list and listens to all dialogs.
                      </div>
                    </div>
                    <input
                      type="checkbox"
                      checked={settings.userAuthAllMessages}
                      onChange={() => setSettings((prev) => ({ ...prev, userAuthAllMessages: !prev.userAuthAllMessages }))}
                      className="h-4 w-4 accent-emerald-500"
                    />
                  </label>
                </div>
              )}

              <div className="flex-1 bg-[#0A0A0B] border border-slate-800 rounded-lg p-2 overflow-y-auto max-h-[260px] custom-scrollbar">
                {isLoadingAvailableChats ? (
                  <div className="text-center text-slate-500 text-sm py-6">Loading Telegram chats...</div>
                ) : availableChats.length === 0 ? (
                  <div className="text-center text-slate-500 text-sm py-6">
                    No chats loaded yet. Click "Sync list" after filling credentials for selected mode.
                  </div>
                ) : (
                  <ul className="space-y-1">
                    {availableChats.map((chat) => {
                      const selected = settings.targetChats.includes(chat.id);
                      const chatInitial = chat.title.trim().charAt(0).toUpperCase() || '?';
                      return (
                        <li key={chat.id}>
                          <button
                            type="button"
                            onClick={() => handleToggleAvailableChat(chat.id)}
                            className={cn(
                              "w-full flex items-center gap-3 px-3 py-2 rounded-md border transition-colors text-left",
                              selected
                                ? "border-emerald-500/30 bg-emerald-500/10"
                                : "border-transparent hover:border-slate-700 hover:bg-slate-800/40"
                            )}
                          >
                            <div
                              className={cn(
                                "w-4 h-4 rounded border flex items-center justify-center text-[10px] font-bold",
                                selected
                                  ? "border-emerald-400 text-emerald-300 bg-emerald-500/20"
                                  : "border-slate-600 text-transparent"
                              )}
                            >
                              v
                            </div>
                            <div className="w-9 h-9 rounded-full overflow-hidden bg-slate-800 border border-slate-700 shrink-0 flex items-center justify-center text-xs text-slate-300 font-semibold">
                              {chat.avatar ? (
                                <img src={chat.avatar} alt={chat.title} className="w-full h-full object-cover" />
                              ) : (
                                <span>{chatInitial}</span>
                              )}
                            </div>
                            <div className="min-w-0 flex-1">
                              <div className="text-sm text-slate-200 truncate">{chat.title}</div>
                              <div className="text-[11px] text-slate-500 truncate">
                                {chat.username ? `@${chat.username}` : chat.id}
                              </div>
                            </div>
                            <span className="text-[10px] uppercase tracking-wide text-slate-400 bg-slate-800/80 border border-slate-700 px-2 py-1 rounded">
                              {chat.type}
                            </span>
                          </button>
                        </li>
                      );
                    })}
                  </ul>
                )}
              </div>

              <div className="flex items-center justify-between text-xs text-slate-500">
                <span>Selected targets: {settings.targetChats.length}</span>
                <span>Selected in list: {selectedAvailableCount} / {availableChats.length}</span>
              </div>
              {settings.authMode === 'user' && settings.userAuthAllMessages && (
                <div className="text-[11px] text-emerald-300">
                  All incoming account messages mode is enabled. Target list is saved but ignored while this mode is on.
                </div>
              )}

              <div className="pt-4 border-t border-slate-800 space-y-3">
                <label className="text-xs font-medium text-slate-400 uppercase tracking-wider">
                  Manual target (optional)
                </label>
                <div className="flex space-x-2">
                  <input
                    type="text"
                    value={settings.newChatInput}
                    onChange={e => setSettings({...settings, newChatInput: e.target.value})}
                    onKeyDown={e => e.key === 'Enter' && handleAddChat()}
                    className="flex-1 bg-[#0A0A0B] border border-slate-700 rounded-lg px-4 py-2 text-sm text-slate-200 focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500 transition-all"
                    placeholder="@username, t.me/link, or numeric chat id"
                  />
                  <button
                    type="button"
                    onClick={handleAddChat}
                    className="bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20 border border-emerald-500/20 px-4 py-2 rounded-lg transition-colors flex items-center"
                  >
                    <Plus className="w-4 h-4" />
                  </button>
                </div>

                {manualTargetChats.length > 0 && (
                  <div className="bg-[#0A0A0B] border border-slate-800 rounded-lg p-2">
                    <div className="text-[11px] uppercase tracking-wide text-slate-500 mb-2">Manual targets</div>
                    <ul className="space-y-1">
                      {manualTargetChats.map((chatId) => (
                        <li key={chatId} className="flex items-center justify-between px-2 py-1.5 rounded hover:bg-slate-800/50">
                          <span className="text-xs text-slate-300 font-mono">{chatId}</span>
                          <button
                            type="button"
                            onClick={() => handleRemoveChat(chatId)}
                            className="text-slate-500 hover:text-red-400"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            </div>
          </div>
          )}
          {section === 'engine' && (
          <div className="bg-[#111113] border border-slate-800 rounded-xl shadow-sm overflow-hidden flex flex-col">
            <div className="px-6 py-4 border-b border-slate-800 bg-slate-900/30 flex items-center">
              <MessageSquare className="w-5 h-5 mr-3 text-amber-400" />
              <h2 className="text-base font-semibold text-slate-200">Триггеры по ключевым словам</h2>
            </div>
            <div className="p-6 flex-1 flex flex-col space-y-5">
              <div className="flex space-x-2 mb-4">
                <input 
                  type="text" 
                  value={settings.newKeywordInput}
                  onChange={e => setSettings({...settings, newKeywordInput: e.target.value})}
                  onKeyDown={e => e.key === 'Enter' && handleAddKeyword()}
                  className="flex-1 bg-[#0A0A0B] border border-slate-700 rounded-lg px-4 py-2 text-sm text-slate-200 focus:outline-none focus:border-amber-500 focus:ring-1 focus:ring-amber-500 transition-all"
                  placeholder="Добавьте ключевое слово или регулярное выражение..."
                />
                <button 
                  onClick={handleAddKeyword}
                  className="bg-amber-500/10 text-amber-400 hover:bg-amber-500/20 border border-amber-500/20 px-4 py-2 rounded-lg transition-colors flex items-center"
                >
                  <Plus className="w-4 h-4" />
                </button>
              </div>
              <div className="flex flex-wrap gap-2">
                {settings.keywords.map((kw, idx) => (
                  <span key={idx} className="inline-flex items-center px-2.5 py-1 rounded-md text-xs font-medium bg-slate-800 text-slate-300 border border-slate-700">
                    {kw}
                    <button onClick={() => handleRemoveKeyword(kw)} className="ml-1.5 text-slate-500 hover:text-red-400">
                      <Trash2 className="w-3 h-3" />
                    </button>
                  </span>
                ))}
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <label className="text-xs font-medium text-slate-400 uppercase tracking-wider">Scam triggers</label>
                  <textarea
                    rows={7}
                    value={triggerArrayToText(settings.scamTriggers)}
                    onChange={(e) => setSettings((prev) => ({ ...prev, scamTriggers: triggerTextToArray(e.target.value) }))}
                    className="w-full bg-[#0A0A0B] border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-amber-500 font-mono"
                  />
                </div>
                <div className="space-y-2">
                  <label className="text-xs font-medium text-slate-400 uppercase tracking-wider">Drug triggers</label>
                  <textarea
                    rows={7}
                    value={triggerArrayToText(settings.drugTriggers)}
                    onChange={(e) => setSettings((prev) => ({ ...prev, drugTriggers: triggerTextToArray(e.target.value) }))}
                    className="w-full bg-[#0A0A0B] border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-amber-500 font-mono"
                  />
                </div>
                <div className="space-y-2">
                  <label className="text-xs font-medium text-slate-400 uppercase tracking-wider">Recruitment triggers</label>
                  <textarea
                    rows={7}
                    value={triggerArrayToText(settings.recruitmentTriggers)}
                    onChange={(e) => setSettings((prev) => ({ ...prev, recruitmentTriggers: triggerTextToArray(e.target.value) }))}
                    className="w-full bg-[#0A0A0B] border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-amber-500 font-mono"
                  />
                </div>
                <div className="space-y-2">
                  <label className="text-xs font-medium text-slate-400 uppercase tracking-wider">Terrorism triggers</label>
                  <textarea
                    rows={7}
                    value={triggerArrayToText(settings.terrorismTriggers)}
                    onChange={(e) => setSettings((prev) => ({ ...prev, terrorismTriggers: triggerTextToArray(e.target.value) }))}
                    className="w-full bg-[#0A0A0B] border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-amber-500 font-mono"
                  />
                </div>
                <div className="space-y-2">
                  <label className="text-xs font-medium text-slate-400 uppercase tracking-wider">Threat triggers</label>
                  <textarea
                    rows={7}
                    value={triggerArrayToText(settings.threatTriggers)}
                    onChange={(e) => setSettings((prev) => ({ ...prev, threatTriggers: triggerTextToArray(e.target.value) }))}
                    className="w-full bg-[#0A0A0B] border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-amber-500 font-mono"
                  />
                </div>
                <div className="space-y-2">
                  <label className="text-xs font-medium text-slate-400 uppercase tracking-wider">Toxicity triggers</label>
                  <textarea
                    rows={7}
                    value={triggerArrayToText(settings.toxicityTriggers)}
                    onChange={(e) => setSettings((prev) => ({ ...prev, toxicityTriggers: triggerTextToArray(e.target.value) }))}
                    className="w-full bg-[#0A0A0B] border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-amber-500 font-mono"
                  />
                </div>
              </div>
            </div>
          </div>
          )}
          {section === 'agents' && (
          <div className="bg-[#111113] border border-slate-800 rounded-xl shadow-sm overflow-hidden flex flex-col">
            <div className="px-6 py-4 border-b border-slate-800 bg-slate-900/30 flex items-center">
              <Database className="w-5 h-5 mr-3 text-cyan-400" />
              <h2 className="text-base font-semibold text-slate-200">ВК (заглушка)</h2>
            </div>
            <div className="p-6 space-y-4">
              <p className="text-sm text-slate-400">
                Здесь будут настройки интеграции VK: токен, список сообществ и режимы мониторинга.
              </p>
              <div className="space-y-2">
                <label className="text-xs font-medium text-slate-500 uppercase tracking-wider">VK Access Token</label>
                <input
                  type="password"
                  disabled
                  className="w-full bg-[#0A0A0B] border border-slate-800 rounded-lg px-4 py-2.5 text-sm text-slate-500 cursor-not-allowed"
                  placeholder="Будет добавлено позже"
                />
              </div>
              <div className="space-y-2">
                <label className="text-xs font-medium text-slate-500 uppercase tracking-wider">Community / Group</label>
                <input
                  type="text"
                  disabled
                  className="w-full bg-[#0A0A0B] border border-slate-800 rounded-lg px-4 py-2.5 text-sm text-slate-500 cursor-not-allowed"
                  placeholder="Например, club123456"
                />
              </div>
              <div className="rounded-lg border border-slate-800 bg-[#0A0A0B] p-3 text-xs text-slate-500">
                Статус: модуль VK пока не подключен.
              </div>
            </div>
          </div>
          )}
          </div>
        )}

        {section === 'proxy' && (
        <div className="bg-[#111113] border border-slate-800 rounded-xl shadow-sm overflow-hidden">
          <div className="px-6 py-4 border-b border-slate-800 bg-slate-900/30 flex items-center justify-between">
            <div className="flex items-center">
              <LinkIcon className="w-5 h-5 mr-3 text-cyan-400" />
              <h2 className="text-base font-semibold text-slate-200">Сеть и прокси</h2>
            </div>
            <label className="flex items-center cursor-pointer">
              <div className="relative">
                <input 
                  type="checkbox" 
                  className="sr-only" 
                  checked={settings.proxyEnabled}
                  onChange={() => setSettings({...settings, proxyEnabled: !settings.proxyEnabled})}
                />
                <div className={cn("block w-10 h-6 rounded-full transition-colors", settings.proxyEnabled ? "bg-cyan-500" : "bg-slate-700")}></div>
                <div className={cn("dot absolute left-1 top-1 bg-white w-4 h-4 rounded-full transition-transform", settings.proxyEnabled ? "transform translate-x-4" : "")}></div>
              </div>
              <span className="ml-3 text-sm font-medium text-slate-300">Включить прокси</span>
            </label>
          </div>
          
          {settings.proxyEnabled && (
            <div className="p-6 grid grid-cols-1 md:grid-cols-5 gap-4 animate-in slide-in-from-top-2 duration-200">
              <div className="space-y-2 md:col-span-1">
                <label className="text-xs font-medium text-slate-400 uppercase tracking-wider">Тип</label>
                <select 
                  value={settings.proxyType}
                  onChange={e => setSettings({...settings, proxyType: e.target.value})}
                  className="w-full bg-[#0A0A0B] border border-slate-700 rounded-lg px-3 py-2.5 text-sm text-slate-200 focus:outline-none focus:border-cyan-500"
                >
                  <option>SOCKS5</option>
                  <option>SOCKS4</option>
                  <option>HTTP</option>
                  <option>MTProto</option>
                </select>
              </div>
              <div className="space-y-2 md:col-span-2">
                <label className="text-xs font-medium text-slate-400 uppercase tracking-wider">Хост / IP</label>
                <input 
                  type="text" 
                  value={settings.proxyHost}
                  onChange={e => setSettings({...settings, proxyHost: e.target.value})}
                  className="w-full bg-[#0A0A0B] border border-slate-700 rounded-lg px-4 py-2.5 text-sm text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
                  placeholder="127.0.0.1"
                />
              </div>
              <div className="space-y-2 md:col-span-2">
                <label className="text-xs font-medium text-slate-400 uppercase tracking-wider">Порт</label>
                <input 
                  type="text" 
                  value={settings.proxyPort}
                  onChange={e => setSettings({...settings, proxyPort: e.target.value})}
                  className="w-full bg-[#0A0A0B] border border-slate-700 rounded-lg px-4 py-2.5 text-sm text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
                  placeholder="1080"
                />
              </div>
              <div className="space-y-2 md:col-span-2 md:col-start-2">
                <label className="text-xs font-medium text-slate-400 uppercase tracking-wider">Имя пользователя (необязательно)</label>
                <input 
                  type="text" 
                  value={settings.proxyUser}
                  onChange={e => setSettings({...settings, proxyUser: e.target.value})}
                  className="w-full bg-[#0A0A0B] border border-slate-700 rounded-lg px-4 py-2.5 text-sm text-slate-200 focus:outline-none focus:border-cyan-500"
                />
              </div>
              <div className="space-y-2 md:col-span-2">
                <label className="text-xs font-medium text-slate-400 uppercase tracking-wider">Пароль (необязательно)</label>
                <input 
                  type="password" 
                  value={settings.proxyPass}
                  onChange={e => setSettings({...settings, proxyPass: e.target.value})}
                  className="w-full bg-[#0A0A0B] border border-slate-700 rounded-lg px-4 py-2.5 text-sm text-slate-200 focus:outline-none focus:border-cyan-500"
                />
              </div>
            </div>
          )}
        </div>
        )}

        {section === 'engine' && (
        <div className="space-y-6">
          <div className="bg-[#111113] border border-slate-800 rounded-xl shadow-sm overflow-hidden">
            <div className="px-6 py-4 border-b border-slate-800 bg-slate-900/30 flex items-center">
              <Cpu className="w-5 h-5 mr-3 text-violet-400" />
              <h2 className="text-base font-semibold text-slate-200">Engine Core</h2>
            </div>
            <div className="p-6 grid grid-cols-1 lg:grid-cols-2 gap-6">
              <div className="space-y-4">
                <div className="space-y-2">
                  <label className="text-xs font-medium text-slate-400 uppercase tracking-wider">Model (local ONNX)</label>
                  <select
                    value={settings.mlModel}
                    onChange={e => setSettings({...settings, mlModel: e.target.value})}
                    className="w-full bg-[#0A0A0B] border border-slate-700 rounded-lg px-3 py-2.5 text-sm text-slate-200 focus:outline-none focus:border-violet-500 font-mono"
                  >
                    {MODEL_OPTIONS.map((model) => (
                      <option key={model.id} value={model.id}>
                        {model.name}
                      </option>
                    ))}
                  </select>
                  <div className="rounded-lg border border-slate-800 bg-[#0A0A0B] p-3">
                    <p className="text-xs text-slate-300">{selectedModel.summary}</p>
                    <p className="text-[11px] text-slate-500 mt-2">Best for: {selectedModel.bestFor}</p>
                  </div>
                </div>

                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <label className="text-xs font-medium text-slate-400 uppercase tracking-wider">Global alert threshold</label>
                    <span className="text-xs font-mono text-violet-400">{settings.threatThreshold}%</span>
                  </div>
                  <input
                    type="range"
                    min="1"
                    max="99"
                    value={settings.threatThreshold}
                    onChange={e => setSettings({...settings, threatThreshold: clampPercent(Number(e.target.value), 1, 99)})}
                    className="w-full accent-violet-500"
                  />
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <label className="flex items-center justify-between rounded-lg border border-slate-800 bg-[#0A0A0B] px-3 py-2">
                    <span className="text-xs text-slate-300">Use heuristics</span>
                    <input
                      type="checkbox"
                      checked={settings.enableHeuristics}
                      onChange={() => setSettings((prev) => ({ ...prev, enableHeuristics: !prev.enableHeuristics }))}
                      className="h-4 w-4 accent-violet-500"
                    />
                  </label>
                  <label className="flex items-center justify-between rounded-lg border border-slate-800 bg-[#0A0A0B] px-3 py-2">
                    <span className="text-xs text-slate-300">Use critical patterns</span>
                    <input
                      type="checkbox"
                      checked={settings.enableCriticalPatterns}
                      onChange={() => setSettings((prev) => ({ ...prev, enableCriticalPatterns: !prev.enableCriticalPatterns }))}
                      className="h-4 w-4 accent-violet-500"
                    />
                  </label>
                </div>
              </div>

              <div className="space-y-4">
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <label className="text-xs font-medium text-slate-400 uppercase tracking-wider">Model weight</label>
                    <span className="text-xs font-mono text-slate-300">{settings.modelWeight}%</span>
                  </div>
                  <input
                    type="range"
                    min="0"
                    max="100"
                    value={settings.modelWeight}
                    onChange={e => setSettings((prev) => ({ ...prev, modelWeight: clampPercent(Number(e.target.value), 0, 100) }))}
                    className="w-full accent-violet-500"
                  />
                </div>
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <label className="text-xs font-medium text-slate-400 uppercase tracking-wider">Heuristic weight</label>
                    <span className="text-xs font-mono text-slate-300">{settings.heuristicWeight}%</span>
                  </div>
                  <input
                    type="range"
                    min="0"
                    max="100"
                    value={settings.heuristicWeight}
                    onChange={e => setSettings((prev) => ({ ...prev, heuristicWeight: clampPercent(Number(e.target.value), 0, 100) }))}
                    className="w-full accent-violet-500"
                  />
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div className="space-y-2">
                    <label className="text-xs font-medium text-slate-400 uppercase tracking-wider">Model top-k</label>
                    <input
                      type="number"
                      min={1}
                      max={30}
                      value={settings.modelTopK}
                      onChange={(e) => setSettings((prev) => ({ ...prev, modelTopK: clampPercent(numberOrFallback(e.target.value, prev.modelTopK), 1, 30) }))}
                      className="w-full bg-[#0A0A0B] border border-slate-700 rounded-lg px-3 py-2.5 text-sm text-slate-200 focus:outline-none focus:border-violet-500"
                    />
                  </div>
                  <div className="space-y-2">
                    <label className="text-xs font-medium text-slate-400 uppercase tracking-wider">Max chars</label>
                    <input
                      type="number"
                      min={200}
                      max={4000}
                      value={settings.maxAnalysisChars}
                      onChange={(e) => setSettings((prev) => ({ ...prev, maxAnalysisChars: clampPercent(numberOrFallback(e.target.value, prev.maxAnalysisChars), 200, 4000) }))}
                      className="w-full bg-[#0A0A0B] border border-slate-700 rounded-lg px-3 py-2.5 text-sm text-slate-200 focus:outline-none focus:border-violet-500"
                    />
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div className="bg-[#111113] border border-slate-800 rounded-xl shadow-sm overflow-hidden">
            <div className="px-6 py-4 border-b border-slate-800 bg-slate-900/30">
              <h3 className="text-sm font-semibold text-slate-200">Category thresholds and boosts</h3>
            </div>
            <div className="p-6 grid grid-cols-1 lg:grid-cols-2 gap-6">
              <div className="space-y-4">
                <div className="grid grid-cols-2 lg:grid-cols-3 gap-3">
                  {(
                    [
                      ['toxicity', 'Toxicity %'],
                      ['threat', 'Threat %'],
                      ['scam', 'Scam %'],
                      ['recruitment', 'Recruitment %'],
                      ['drugs', 'Drugs %'],
                      ['terrorism', 'Terrorism %'],
                    ] as const
                  ).map(([key, label]) => (
                    <div key={key} className="space-y-2">
                      <label className="text-xs font-medium text-slate-400 uppercase tracking-wider">{label}</label>
                      <input
                        type="number"
                        min={1}
                        max={99}
                        value={settings.categoryThresholds[key]}
                        onChange={(e) =>
                          setSettings((prev) => ({
                            ...prev,
                            categoryThresholds: {
                              ...prev.categoryThresholds,
                              [key]: clampPercent(numberOrFallback(e.target.value, prev.categoryThresholds[key]), 1, 99),
                            },
                          }))
                        }
                        className="w-full bg-[#0A0A0B] border border-slate-700 rounded-lg px-3 py-2.5 text-sm text-slate-200 focus:outline-none focus:border-violet-500"
                      />
                    </div>
                  ))}
                </div>

                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <label className="text-xs font-medium text-slate-400 uppercase tracking-wider">URL scam boost</label>
                    <span className="text-xs font-mono text-slate-300">{settings.urlScamBoost}%</span>
                  </div>
                  <input
                    type="range"
                    min="0"
                    max="100"
                    value={settings.urlScamBoost}
                    onChange={e => setSettings((prev) => ({ ...prev, urlScamBoost: clampPercent(Number(e.target.value), 0, 100) }))}
                    className="w-full accent-violet-500"
                  />
                </div>
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <label className="text-xs font-medium text-slate-400 uppercase tracking-wider">Keyword hit boost</label>
                    <span className="text-xs font-mono text-slate-300">{settings.keywordHitBoost}%</span>
                  </div>
                  <input
                    type="range"
                    min="0"
                    max="100"
                    value={settings.keywordHitBoost}
                    onChange={e => setSettings((prev) => ({ ...prev, keywordHitBoost: clampPercent(Number(e.target.value), 0, 100) }))}
                    className="w-full accent-violet-500"
                  />
                </div>
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <label className="text-xs font-medium text-slate-400 uppercase tracking-wider">Critical hit floor</label>
                    <span className="text-xs font-mono text-slate-300">{settings.criticalHitFloor}%</span>
                  </div>
                  <input
                    type="range"
                    min="0"
                    max="100"
                    value={settings.criticalHitFloor}
                    onChange={e => setSettings((prev) => ({ ...prev, criticalHitFloor: clampPercent(Number(e.target.value), 0, 100) }))}
                    className="w-full accent-violet-500"
                  />
                </div>
              </div>

              <div className="space-y-4">
                <label className="text-xs font-medium text-slate-400 uppercase tracking-wider">Media processing</label>
                <div className="space-y-3">
                  <label className="flex items-center cursor-pointer">
                    <div className="relative">
                      <input
                        type="checkbox"
                        className="sr-only"
                        checked={settings.downloadMedia}
                        onChange={() => setSettings({...settings, downloadMedia: !settings.downloadMedia})}
                      />
                      <div className={cn("block w-10 h-6 rounded-full transition-colors", settings.downloadMedia ? "bg-violet-500" : "bg-slate-700")}></div>
                      <div className={cn("dot absolute left-1 top-1 bg-white w-4 h-4 rounded-full transition-transform", settings.downloadMedia ? "transform translate-x-4" : "")}></div>
                    </div>
                    <span className="ml-3 text-sm font-medium text-slate-300">Download media for analysis</span>
                  </label>

                  {settings.downloadMedia && (
                    <div className="pl-12 grid grid-cols-2 gap-3 animate-in fade-in duration-200">
                      <label className="flex items-center space-x-2 cursor-pointer">
                        <input type="checkbox" checked={settings.mediaTypes.photo} onChange={e => setSettings(s => ({...s, mediaTypes: {...s.mediaTypes, photo: e.target.checked}}))} className="rounded border-slate-700 text-violet-500 focus:ring-violet-500 bg-[#0A0A0B]" />
                        <ImageIcon className="w-4 h-4 text-slate-400" />
                        <span className="text-sm text-slate-300">Photo (OCR)</span>
                      </label>
                      <label className="flex items-center space-x-2 cursor-pointer">
                        <input type="checkbox" checked={settings.mediaTypes.video} onChange={e => setSettings(s => ({...s, mediaTypes: {...s.mediaTypes, video: e.target.checked}}))} className="rounded border-slate-700 text-violet-500 focus:ring-violet-500 bg-[#0A0A0B]" />
                        <Video className="w-4 h-4 text-slate-400" />
                        <span className="text-sm text-slate-300">Video</span>
                      </label>
                      <label className="flex items-center space-x-2 cursor-pointer">
                        <input type="checkbox" checked={settings.mediaTypes.document} onChange={e => setSettings(s => ({...s, mediaTypes: {...s.mediaTypes, document: e.target.checked}}))} className="rounded border-slate-700 text-violet-500 focus:ring-violet-500 bg-[#0A0A0B]" />
                        <FileText className="w-4 h-4 text-slate-400" />
                        <span className="text-sm text-slate-300">Documents</span>
                      </label>
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>

          <div className="bg-[#111113] border border-slate-800 rounded-xl shadow-sm overflow-hidden">
            <div className="px-6 py-4 border-b border-slate-800 bg-slate-900/30 flex items-center justify-between">
              <h3 className="text-sm font-semibold text-slate-200">Engine self-test</h3>
              <button
                type="button"
                onClick={() => void runEngineSelfTest()}
                disabled={isRunningEngineTest || cooldowns.engineTest > 0}
                className={cn(
                  "px-3 py-2 rounded-lg border text-xs font-medium transition-colors",
                  isRunningEngineTest || cooldowns.engineTest > 0
                    ? "border-slate-700 text-slate-500 cursor-not-allowed"
                    : "border-violet-500/20 text-violet-300 hover:bg-violet-500/10"
                )}
              >
                {isRunningEngineTest
                  ? 'Running...'
                  : cooldowns.engineTest > 0
                    ? 'Cooldown ' + cooldownText('engineTest')
                    : 'Run Self-Test'}
              </button>
            </div>
            <div className="p-6 space-y-4">
              <div className="rounded-lg border border-slate-800 bg-[#0A0A0B] p-4 space-y-3">
                <div className="space-y-1">
                  <label className="text-xs font-medium text-slate-400 uppercase tracking-wider">Built-in dataset preset</label>
                  <p className="text-[11px] text-slate-500">{selectedEnginePreset.description}</p>
                </div>
                <div className="flex flex-wrap gap-2">
                  {ENGINE_SELF_TEST_PRESET_OPTIONS.map((preset) => (
                    <button
                      key={preset.id}
                      type="button"
                      onClick={() => setEngineTestPreset(preset.id)}
                      className={cn(
                        "px-2.5 py-1.5 rounded-md border text-xs transition-colors",
                        engineTestPreset === preset.id
                          ? "border-violet-500/40 bg-violet-500/10 text-violet-200"
                          : "border-slate-700 text-slate-300 hover:border-slate-600 hover:text-slate-200"
                      )}
                    >
                      {preset.label}
                    </button>
                  ))}
                </div>
                <div className="flex flex-wrap gap-2">
                  <button
                    type="button"
                    onClick={() => {
                      if (engineTestPreset === 'all') {
                        setEngineTestInput((Object.values(SELF_TEST_PRESET_MESSAGES) as string[][]).flat().join('\n'));
                        return;
                      }
                      setEngineTestInput(SELF_TEST_PRESET_MESSAGES[engineTestPreset].join('\n'));
                    }}
                    className="px-2.5 py-1.5 rounded-md border border-slate-700 text-xs text-slate-300 hover:border-slate-600 hover:text-slate-200 transition-colors"
                  >
                    Load preset into custom input
                  </button>
                  <button
                    type="button"
                    onClick={() => setEngineTestInput('')}
                    className="px-2.5 py-1.5 rounded-md border border-slate-700 text-xs text-slate-300 hover:border-slate-600 hover:text-slate-200 transition-colors"
                  >
                    Clear custom input
                  </button>
                </div>
              </div>

              <div className="space-y-2">
                <label className="text-xs font-medium text-slate-400 uppercase tracking-wider">Preset messages by category</label>
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
                  {(Object.entries(SELF_TEST_PRESET_MESSAGES) as Array<[EngineSelfTestCategory, string[]]>).map(
                    ([category, presetMessages]) => (
                      <div key={category} className="rounded-lg border border-slate-800 bg-[#0A0A0B] p-3">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-medium text-slate-200">
                            {ENGINE_SELF_TEST_PRESET_OPTIONS.find((preset) => preset.id === category)?.label ?? category}
                          </span>
                          <span className="text-[11px] text-slate-500">{presetMessages.length} msgs</span>
                        </div>
                        <div className="mt-2 space-y-1">
                          {presetMessages.map((message, presetIndex) => (
                            <div key={`${category}-${presetIndex}`} className="text-[11px] text-slate-400">
                              {presetIndex + 1}. {message}
                            </div>
                          ))}
                        </div>
                      </div>
                    )
                  )}
                </div>
              </div>

              <div className="space-y-2">
                <label className="text-xs font-medium text-slate-400 uppercase tracking-wider">Custom test messages (optional)</label>
                <textarea
                  rows={5}
                  value={engineTestInput}
                  onChange={(e) => setEngineTestInput(e.target.value)}
                  className="w-full bg-[#0A0A0B] border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-violet-500 font-mono"
                  placeholder={'One message per line. If this field is empty, selected preset dataset is used.'}
                />
                <p className="text-[11px] text-slate-500">
                  {engineTestUsedDefaultSet
                    ? `Last run used preset dataset: ${lastUsedEnginePresetLabel}.`
                    : 'Last run used custom messages from this field.'}
                </p>
              </div>

              {engineTestSummary && (
                <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-3">
                  {(THREAT_TYPES as ThreatLabel[]).map((type) => (
                    <div key={`summary-${type}`} className="rounded-lg border border-slate-800 bg-[#0A0A0B] p-3 text-xs text-slate-300">
                      {THREAT_LABELS[type]}: {engineTestSummary[type]}
                    </div>
                  ))}
                </div>
              )}

              {engineTestResults.length > 0 && (
                <div className="space-y-2 max-h-[380px] overflow-y-auto pr-1">
                  {engineTestResults.map((result, index) => (
                    <div key={result.text + '-' + index} className="rounded-lg border border-slate-800 bg-[#0A0A0B] p-3">
                      <div className="flex items-center justify-between gap-3">
                        <span className="text-xs text-slate-400 uppercase tracking-wider">{result.scenario}</span>
                        <span className="text-xs text-slate-200 font-mono">{result.type} {result.confidence}%</span>
                      </div>
                      {result.expected && (
                        <div className="text-[11px] text-slate-500 mt-1">Expected: {result.expected}</div>
                      )}
                      <pre className="mt-2 text-xs text-slate-300 whitespace-pre-wrap break-words font-sans">{result.text}</pre>
                      <div className="mt-2 grid grid-cols-2 md:grid-cols-3 gap-2 text-[11px] text-slate-400">
                        {ENGINE_RISK_KEYS.map((riskKey) => (
                          <div key={`${result.text}-${riskKey}`}>
                            {THREAT_LABELS[riskKey]} {result.scores[riskKey]}% / thr {result.thresholds[riskKey]}%
                          </div>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
        )}

        {/* Save Button */}
        <div className="flex justify-end pt-4">
          <button
            onClick={() => void saveSettings(true)}
            disabled={isSavingSettings || cooldowns.saveSettings > 0}
            className={cn(
              "text-white px-6 py-2.5 rounded-lg font-medium transition-colors flex items-center shadow-lg shadow-indigo-500/20",
              isSavingSettings || cooldowns.saveSettings > 0
                ? "bg-indigo-800 cursor-not-allowed opacity-80"
                : "bg-indigo-600 hover:bg-indigo-700"
            )}
          >
            <Save className="w-4 h-4 mr-2" />
            {isSavingSettings
              ? 'Сохранение...'
              : cooldowns.saveSettings > 0
                ? `Кд ${cooldownText('saveSettings')}`
                : 'Сохранить конфигурацию'}
          </button>
        </div>
      </div>
    );
  };

  return (
    <div className="min-h-screen bg-[#0A0A0B] text-slate-200 font-sans flex">
      
      {/* SIDEBAR */}
      <aside className="w-64 flex-shrink-0 border-r border-slate-800/60 bg-[#0A0A0B] flex flex-col">
        <div className="h-16 flex items-center px-6 border-b border-slate-800/60">
          <div className="w-8 h-8 rounded-lg bg-indigo-500/20 flex items-center justify-center border border-indigo-500/30 mr-3">
            <Shield className="w-5 h-5 text-indigo-400" />
          </div>
          <h1 className="text-lg font-semibold tracking-tight text-slate-100">Sentinel AI</h1>
        </div>
        
        <nav className="flex-1 px-4 py-6 space-y-1">
          <button 
            onClick={() => setActiveTab('dashboard')}
            className={cn(
              "w-full flex items-center px-3 py-2.5 rounded-lg text-sm font-medium transition-colors",
              activeTab === 'dashboard' ? "bg-indigo-500/10 text-indigo-400" : "text-slate-400 hover:bg-slate-800/50 hover:text-slate-200"
            )}
          >
            <Activity className="w-4 h-4 mr-3" /> Панель
          </button>
          {user.role === 'admin' && (
            <>
              <button
                onClick={() => setActiveTab('agents')}
                className={cn(
                  "w-full flex items-center px-3 py-2.5 rounded-lg text-sm font-medium transition-colors",
                  activeTab === 'agents' ? "bg-indigo-500/10 text-indigo-400" : "text-slate-400 hover:bg-slate-800/50 hover:text-slate-200"
                )}
              >
                <Settings className="w-4 h-4 mr-3" /> {'\u0410\u0433\u0435\u043d\u0442\u044b'}
              </button>
              <button
                onClick={() => setActiveTab('engine')}
                className={cn(
                  "w-full flex items-center px-3 py-2.5 rounded-lg text-sm font-medium transition-colors",
                  activeTab === 'engine' ? "bg-indigo-500/10 text-indigo-400" : "text-slate-400 hover:bg-slate-800/50 hover:text-slate-200"
                )}
              >
                <Cpu className="w-4 h-4 mr-3" /> {'\u041d\u0430\u0441\u0442\u0440\u043e\u0439\u043a\u0430 \u0434\u0432\u0438\u0436\u043a\u0430'}
              </button>
              <button
                onClick={() => setActiveTab('proxy')}
                className={cn(
                  "w-full flex items-center px-3 py-2.5 rounded-lg text-sm font-medium transition-colors",
                  activeTab === 'proxy' ? "bg-indigo-500/10 text-indigo-400" : "text-slate-400 hover:bg-slate-800/50 hover:text-slate-200"
                )}
              >
                <LinkIcon className="w-4 h-4 mr-3" /> {'\u041f\u0440\u043e\u043a\u0441\u0438'}
              </button>
            </>
          )}
          <button 
            onClick={() => setActiveTab('logs')}
            className={cn(
              "w-full flex items-center px-3 py-2.5 rounded-lg text-sm font-medium transition-colors",
              activeTab === 'logs' ? "bg-indigo-500/10 text-indigo-400" : "text-slate-400 hover:bg-slate-800/50 hover:text-slate-200"
            )}
          >
            <Database className="w-4 h-4 mr-3" /> Системные журналы
          </button>
        </nav>

        <div className="p-4 border-t border-slate-800/60">
          <div className="bg-slate-900/50 rounded-lg p-3 border border-slate-800">
            <div className="text-xs font-medium text-slate-400 mb-2 uppercase tracking-wider">Статус движка</div>
            <div className="flex items-center">
              <div className={cn("w-2 h-2 rounded-full mr-2", isRunning ? "bg-emerald-500 animate-pulse" : "bg-slate-600")}></div>
              <span className="text-sm font-medium text-slate-200">{isRunning ? 'Активен и слушает' : 'Не в сети'}</span>
            </div>
          </div>
        </div>
      </aside>

      {/* MAIN CONTENT */}
      <main className="flex-1 flex flex-col min-w-0 overflow-hidden relative">
        {/* Header */}
        <header className="h-16 border-b border-slate-800/60 bg-[#0A0A0B]/80 backdrop-blur-md flex items-center justify-between px-8 sticky top-0 z-10">
          <h2 className="text-lg font-medium text-slate-100 capitalize">
            {activeTab === 'dashboard' ? 'Панель' : activeTab === 'agents' ? 'Агенты' : activeTab === 'engine' ? 'Настройка движка' : activeTab === 'proxy' ? 'Прокси' : 'Системные журналы'}
          </h2>
          
          <div className="flex items-center space-x-4">
            {user.role === 'admin' && (
              <button
                onClick={toggleEngine}
                disabled={cooldowns.engineControl > 0}
                className={cn(
                  "flex items-center px-4 py-2 rounded-lg text-sm font-medium transition-all shadow-sm",
                  cooldowns.engineControl > 0 && "opacity-60 cursor-not-allowed",
                  isRunning 
                    ? "bg-red-500/10 text-red-400 hover:bg-red-500/20 border border-red-500/20" 
                    : "bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20 border border-emerald-500/20"
                )}
              >
                {cooldowns.engineControl > 0 ? (
                  <><Square className="w-4 h-4 mr-2 fill-current" /> КД {cooldownText('engineControl')}</>
                ) : isRunning ? (
                  <><Square className="w-4 h-4 mr-2 fill-current" /> Остановить движок</>
                ) : (
                  <><Play className="w-4 h-4 mr-2 fill-current" /> Запустить движок</>
                )}
              </button>
            )}
             <button
              onClick={logout}
              className="text-slate-400 hover:text-white transition-colors"
            >
              Logout
            </button>
          </div>
        </header>

        {/* Scrollable Content */}
        <div className="flex-1 overflow-y-auto p-8 custom-scrollbar">
          {activeTab === 'dashboard' && renderDashboard()}
          {activeTab === 'agents' && renderSettings('agents')}
          {activeTab === 'engine' && renderSettings('engine')}
          {activeTab === 'proxy' && renderSettings('proxy')}
          {activeTab === 'logs' && (
            <div className="flex flex-col items-center justify-center h-full text-slate-500 space-y-4">
              <Terminal className="w-12 h-12 opacity-20" />
              <p className="font-mono text-sm">Системные журналы появятся здесь при подключении к бэкенду.</p>
            </div>
          )}
        </div>
      </main>
    </div>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <Router>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route element={<PrivateRoute />}>
            <Route path="/" element={<SentinelApp />} />
          </Route>
        </Routes>
      </Router>
    </AuthProvider>
  )
}

