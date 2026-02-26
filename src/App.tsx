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
const THREAT_TYPES = ['safe', 'toxicity', 'threat', 'scam'];
const THREAT_COLORS = {
  safe: '#10b981', // emerald-500
  toxicity: '#f59e0b', // amber-500
  threat: '#ef4444', // red-500
  scam: '#8b5cf6' // violet-500
};

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
];

type SettingsState = {
  apiId: string;
  apiHash: string;
  authMode: 'bot' | 'user';
  botToken: string;
  sessionString: string;
  sessionName: string;
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
  mlModel: string;
  threatThreshold: number;
};

type AvailableTelegramChat = {
  id: string;
  title: string;
  username: string | null;
  type: 'group' | 'supergroup' | 'channel';
  avatar: string | null;
};

const DEFAULT_SETTINGS: SettingsState = {
  apiId: '',
  apiHash: '',
  authMode: 'bot',
  botToken: '',
  sessionString: '',
  sessionName: 'sentinel_session',
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
  keywords: ['crypto', 'hack', 'buy', 'sell', 'leak'],
  newKeywordInput: '',
  mlModel: MODEL_OPTIONS[0].id,
  threatThreshold: 75,
};

// --- MAIN APP COMPONENT ---
function SentinelApp() {
  const { user, logout } = useAuth();
  const [activeTab, setActiveTab] = useState<'панель' | 'настройки' | 'журналы'>('панель');
  const [isRunning, setIsRunning] = useState(false);
  
  // Dashboard State
  const [messages, setMessages] = useState<any[]>([]);
  const [stats, setStats] = useState<{ safe: number; toxicity: number; threat: number; scam: number }>({ safe: 0, toxicity: 0, threat: 0, scam: 0 });
  
  // Settings State
  const [settings, setSettings] = useState<SettingsState>(DEFAULT_SETTINGS);
  const [isSavingSettings, setIsSavingSettings] = useState(false);
  const [availableChats, setAvailableChats] = useState<AvailableTelegramChat[]>([]);
  const [isLoadingAvailableChats, setIsLoadingAvailableChats] = useState(false);
  const selectedModel = MODEL_OPTIONS.find((model) => model.id === settings.mlModel) ?? MODEL_OPTIONS[0];

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
          setStats(statsData);
        }
      } catch (err) {
        console.error('Не удалось получить статус', err);
      }
    };

    checkStatus();
    interval = setInterval(checkStatus, 2000);
    
    return () => clearInterval(interval);
  }, [logout]);

  const toPersistedSettingsPayload = (source: SettingsState) => ({
    apiId: source.apiId,
    apiHash: source.apiHash,
    authMode: source.authMode,
    botToken: source.botToken,
    sessionString: source.sessionString,
    sessionName: source.sessionName,
    targetChats: source.targetChats,
    proxyEnabled: source.proxyEnabled,
    proxyType: source.proxyType,
    proxyHost: source.proxyHost,
    proxyPort: source.proxyPort,
    proxyUser: source.proxyUser,
    proxyPass: source.proxyPass,
    downloadMedia: source.downloadMedia,
    mediaTypes: source.mediaTypes,
    keywords: source.keywords,
    mlModel: source.mlModel,
    threatThreshold: source.threatThreshold,
  });

  const loadAvailableChats = async (
    credentials?: Partial<Pick<SettingsState, 'apiId' | 'apiHash' | 'authMode' | 'botToken' | 'sessionString'>>,
    showNotification = true
  ): Promise<void> => {
    if (!user || user.role !== 'admin') return;

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

      setAvailableChats(chats);
    } catch (err) {
      console.error('Failed to load available Telegram chats', err);
      if (showNotification) {
        alert(`Failed to load Telegram chats: ${(err as Error).message}`);
      }
    } finally {
      setIsLoadingAvailableChats(false);
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

        setSettings((prev) => ({
          ...prev,
          ...saved,
          authMode: saved?.authMode === 'user' || saved?.authMode === 'bot' ? saved.authMode : prev.authMode,
          sessionString: typeof saved?.sessionString === 'string' ? saved.sessionString : prev.sessionString,
          targetChats: Array.isArray(saved?.targetChats) ? saved.targetChats : prev.targetChats,
          keywords: Array.isArray(saved?.keywords) ? saved.keywords : prev.keywords,
          mediaTypes: {
            ...prev.mediaTypes,
            ...(saved?.mediaTypes ?? {}),
          },
          newChatInput: '',
          newKeywordInput: '',
        }));

      } catch (err) {
        console.error('Failed to load saved settings', err);
      }
    };

    loadSettings();
    return () => {
      cancelled = true;
    };
  }, [user]);

  const saveSettings = async (showNotification = true): Promise<boolean> => {
    if (!user || user.role !== 'admin') return false;
    setIsSavingSettings(true);

    try {
      const res = await fetch('/api/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(toPersistedSettingsPayload(settings)),
      });

      const data = await res.json();
      if (!res.ok) {
        if (showNotification) {
          alert(data.error ?? 'Не удалось сохранить конфигурацию');
        }
        return false;
      }

      if (data?.settings) {
        setSettings((prev) => ({
          ...prev,
          ...data.settings,
          newChatInput: '',
          newKeywordInput: '',
        }));
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
    try {
      if (isRunning) {
        await fetch('/api/stop', { method: 'POST' });
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
            chats: settings.targetChats,
            model: settings.mlModel,
            threatThreshold: settings.threatThreshold / 100
          })
        });
        const data = await res.json();
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

  // --- HANDLERS ---
  const handleAddChat = () => {
    const normalizedChat = settings.newChatInput.trim();
    if (normalizedChat && !settings.targetChats.includes(normalizedChat)) {
      setSettings(s => ({ ...s, targetChats: [...s.targetChats, normalizedChat], newChatInput: '' }));
    }
  };

  const handleRemoveChat = (chat: string) => {
    setSettings(s => ({ ...s, targetChats: s.targetChats.filter(c => c !== chat) }));
  };

  const handleToggleAvailableChat = (chatId: string) => {
    setSettings((prev) => {
      const isSelected = prev.targetChats.includes(chatId);
      return {
        ...prev,
        targetChats: isSelected
          ? prev.targetChats.filter((chat) => chat !== chatId)
          : [...prev.targetChats, chatId],
      };
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

  // --- RENDERERS ---
  const renderDashboard = () => {
        const pieData = Object.entries(stats).map(([name, value]) => ({ name, value }));
    const totalMessages: number = stats.safe + stats.toxicity + stats.threat + stats.scam;
    const sumThreats: number = stats.toxicity + stats.threat + stats.scam;
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
                            "bg-violet-500/10 text-violet-400 border border-violet-500/20"
                          )}>
                            {msg.type}
                          </span>
                        </div>
                      </div>
                      <p className="text-sm text-slate-300 leading-relaxed">{msg.text}</p>
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

  const renderSettings = () => {
    if (user.role !== 'admin') return null;
    return (
      <div className="space-y-6 animate-in fade-in duration-300 max-w-5xl mx-auto pb-12">
        
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
                onChange={e => setSettings({...settings, authMode: e.target.value as 'bot' | 'user'})}
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
              <div className="space-y-2">
                <label className="text-xs font-medium text-slate-400 uppercase tracking-wider">Session String</label>
                <textarea
                  value={settings.sessionString}
                  onChange={e => setSettings({...settings, sessionString: e.target.value})}
                  rows={3}
                  className="w-full bg-[#0A0A0B] border border-slate-700 rounded-lg px-4 py-2.5 text-sm text-slate-200 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all font-mono"
                  placeholder="Paste Telegram String Session for your account"
                />
                <p className="text-[11px] text-amber-500 mt-1">Account mode uses your Telegram account dialogs directly.</p>
              </div>
            )}
          </div>
        </div>

        {/* Section 2: Targets & Filters */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Targets */}
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
                <button
                  type="button"
                  onClick={() => void loadAvailableChats(undefined, true)}
                  disabled={isLoadingAvailableChats}
                  className={cn(
                    "inline-flex items-center gap-2 px-3 py-2 rounded-lg border text-xs font-medium transition-colors",
                    isLoadingAvailableChats
                      ? "border-slate-700 text-slate-500 cursor-not-allowed"
                      : "border-emerald-500/20 text-emerald-400 hover:bg-emerald-500/10"
                  )}
                >
                  <RefreshCw className={cn("w-4 h-4", isLoadingAvailableChats && "animate-spin")} />
                  {isLoadingAvailableChats ? 'Syncing...' : 'Sync list'}
                </button>
              </div>

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
                <span>Available chats: {availableChats.length}</span>
              </div>

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
          {/* Keyword Filters */}
          <div className="bg-[#111113] border border-slate-800 rounded-xl shadow-sm overflow-hidden flex flex-col">
            <div className="px-6 py-4 border-b border-slate-800 bg-slate-900/30 flex items-center">
              <MessageSquare className="w-5 h-5 mr-3 text-amber-400" />
              <h2 className="text-base font-semibold text-slate-200">Триггеры по ключевым словам</h2>
            </div>
            <div className="p-6 flex-1 flex flex-col">
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
            </div>
          </div>
        </div>

        {/* Section 3: Connection & Proxy */}
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

        {/* Section 4: ML & Processing */}
        <div className="bg-[#111113] border border-slate-800 rounded-xl shadow-sm overflow-hidden">
          <div className="px-6 py-4 border-b border-slate-800 bg-slate-900/30 flex items-center">
            <Cpu className="w-5 h-5 mr-3 text-violet-400" />
            <h2 className="text-base font-semibold text-slate-200">Движок анализа</h2>
          </div>
          <div className="p-6 grid grid-cols-1 md:grid-cols-2 gap-8">
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
                  <label className="text-xs font-medium text-slate-400 uppercase tracking-wider">Порог оповещения</label>
                  <span className="text-xs font-mono text-violet-400">{settings.threatThreshold}%</span>
                </div>
                <input 
                  type="range" 
                  min="1" max="99" 
                  value={settings.threatThreshold}
                  onChange={e => setSettings({...settings, threatThreshold: parseInt(e.target.value)})}
                  className="w-full accent-violet-500"
                />
                <p className="text-[11px] text-slate-500">Срабатывать только в том случае, если показатель уверенности превышает это значение.</p>
              </div>
            </div>

            <div className="space-y-4">
              <label className="text-xs font-medium text-slate-400 uppercase tracking-wider">Обработка медиа</label>
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
                  <span className="ml-3 text-sm font-medium text-slate-300">Скачивать медиа для анализа</span>
                </label>
                
                {settings.downloadMedia && (
                  <div className="pl-12 grid grid-cols-2 gap-3 animate-in fade-in duration-200">
                    <label className="flex items-center space-x-2 cursor-pointer">
                      <input type="checkbox" checked={settings.mediaTypes.photo} onChange={e => setSettings(s => ({...s, mediaTypes: {...s.mediaTypes, photo: e.target.checked}}))} className="rounded border-slate-700 text-violet-500 focus:ring-violet-500 bg-[#0A0A0B]" />
                      <ImageIcon className="w-4 h-4 text-slate-400" />
                      <span className="text-sm text-slate-300">Фото (OCR)</span>
                    </label>
                    <label className="flex items-center space-x-2 cursor-pointer">
                      <input type="checkbox" checked={settings.mediaTypes.video} onChange={e => setSettings(s => ({...s, mediaTypes: {...s.mediaTypes, video: e.target.checked}}))} className="rounded border-slate-700 text-violet-500 focus:ring-violet-500 bg-[#0A0A0B]" />
                      <Video className="w-4 h-4 text-slate-400" />
                      <span className="text-sm text-slate-300">Видео</span>
                    </label>
                    <label className="flex items-center space-x-2 cursor-pointer">
                      <input type="checkbox" checked={settings.mediaTypes.document} onChange={e => setSettings(s => ({...s, mediaTypes: {...s.mediaTypes, document: e.target.checked}}))} className="rounded border-slate-700 text-violet-500 focus:ring-violet-500 bg-[#0A0A0B]" />
                      <FileText className="w-4 h-4 text-slate-400" />
                      <span className="text-sm text-slate-300">Документы</span>
                    </label>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>

        {/* Save Button */}
        <div className="flex justify-end pt-4">
          <button
            onClick={() => void saveSettings(true)}
            disabled={isSavingSettings}
            className={cn(
              "text-white px-6 py-2.5 rounded-lg font-medium transition-colors flex items-center shadow-lg shadow-indigo-500/20",
              isSavingSettings
                ? "bg-indigo-800 cursor-not-allowed opacity-80"
                : "bg-indigo-600 hover:bg-indigo-700"
            )}
          >
            <Save className="w-4 h-4 mr-2" />
            {isSavingSettings ? 'Сохранение...' : 'Сохранить конфигурацию'}
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
            onClick={() => setActiveTab('панель')}
            className={cn(
              "w-full flex items-center px-3 py-2.5 rounded-lg text-sm font-medium transition-colors",
              activeTab === 'панель' ? "bg-indigo-500/10 text-indigo-400" : "text-slate-400 hover:bg-slate-800/50 hover:text-slate-200"
            )}
          >
            <Activity className="w-4 h-4 mr-3" /> Панель
          </button>
          {user.role === 'admin' && (
            <button 
              onClick={() => setActiveTab('настройки')}
              className={cn(
                "w-full flex items-center px-3 py-2.5 rounded-lg text-sm font-medium transition-colors",
                activeTab === 'настройки' ? "bg-indigo-500/10 text-indigo-400" : "text-slate-400 hover:bg-slate-800/50 hover:text-slate-200"
              )}
            >
              <Settings className="w-4 h-4 mr-3" /> Конфигурация
            </button>
          )}
          <button 
            onClick={() => setActiveTab('журналы')}
            className={cn(
              "w-full flex items-center px-3 py-2.5 rounded-lg text-sm font-medium transition-colors",
              activeTab === 'журналы' ? "bg-indigo-500/10 text-indigo-400" : "text-slate-400 hover:bg-slate-800/50 hover:text-slate-200"
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
            {activeTab === 'настройки' && user.role !== 'admin' ? 'Панель' : activeTab}
          </h2>
          
          <div className="flex items-center space-x-4">
            {user.role === 'admin' && (
              <button
                onClick={toggleEngine}
                className={cn(
                  "flex items-center px-4 py-2 rounded-lg text-sm font-medium transition-all shadow-sm",
                  isRunning 
                    ? "bg-red-500/10 text-red-400 hover:bg-red-500/20 border border-red-500/20" 
                    : "bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20 border border-emerald-500/20"
                )}
              >
                {isRunning ? (
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
          {activeTab === 'панель' && renderDashboard()}
          {activeTab === 'настройки' && renderSettings()}
          {activeTab === 'журналы' && (
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


