import React, { useState } from 'react';
import {
  ShieldCheck,
  User,
  Key,
  LogOut,
  X,
  AlertCircle,
  CheckCircle2,
  Lock,
  ArrowRight,
  UserCheck,
} from 'lucide-react';
import { UserSessionProfile, loginUser, logoutUser } from '../services/api';

interface AuthModalProps {
  isOpen: boolean;
  onClose: () => void;
  currentUser: UserSessionProfile | null;
  onSessionChange: (user: UserSessionProfile | null) => void;
}

const PRESET_OPERATORS = [
  {
    email: 'analyst@soc.internal',
    password: 'Analyst@SOC2026!',
    name: 'Primary SOC Analyst',
    role: 'ANALYST' as const,
    badge: 'SOC-9042',
    description: 'Lead Incident Responder. Access to authorized investigation cases and evidence verification.',
  },
  {
    email: 'analyst2@soc.internal',
    password: 'Analyst2@SOC2026!',
    name: 'Forensic Investigator Alex Rivera',
    role: 'ANALYST' as const,
    badge: 'SOC-7718',
    description: 'Forensic Investigator. Demonstrates cross-analyst case isolation & ownership boundaries.',
  },
  {
    email: 'vikneshwarann.25it@kongu.edu',
    password: 'Vikneshwarann@07',
    name: 'Lead SOC Operator Vikneshwaran N',
    role: 'ADMIN' as const,
    badge: 'LEAD-0001',
    description: 'Platform Lead & Administrator. Full SOC oversight and authority across all forensic cases.',
  },
  {
    email: 'admin@soc.internal',
    password: 'Admin@SOC2026!',
    name: 'Chief SOC Security Admin Marcus Vance',
    role: 'ADMIN' as const,
    badge: 'SEC-0001',
    description: 'Administrator role. Full supervisory authority, ledger reseal/tamper controls & audit logs.',
  },
];

export const AuthModal: React.FC<AuthModalProps> = ({
  isOpen,
  onClose,
  currentUser,
  onSessionChange,
}) => {
  const [nameInput, setNameInput] = useState('');
  const [emailInput, setEmailInput] = useState('');
  const [passwordInput, setPasswordInput] = useState('');
  const [roleInput, setRoleInput] = useState<'ANALYST' | 'ADMIN' | 'SENIOR_ANALYST' | 'AUDITOR'>('ANALYST');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleCustomLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSuccessMsg(null);
    setLoading(true);

    try {
      const { user } = await loginUser(emailInput, passwordInput, nameInput || undefined, roleInput);
      onSessionChange(user);
      setSuccessMsg(`Authenticated as ${user.name} (${user.role})`);
      setTimeout(() => {
        onClose();
      }, 700);
    } catch (err: any) {
      setError(err.message || 'Authentication failed');
    } finally {
      setLoading(false);
    }
  };

  const handleQuickSwitch = async (op: (typeof PRESET_OPERATORS)[0]) => {
    setError(null);
    setSuccessMsg(null);
    setLoading(true);

    try {
      const { user } = await loginUser(op.email, op.password, op.name, op.role);
      onSessionChange(user);
      setSuccessMsg(`Switched to ${user.name} (${user.role})`);
      setTimeout(() => {
        onClose();
      }, 700);
    } catch (err: any) {
      setError(err.message || 'Operator switch failed');
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = async () => {
    setLoading(true);
    try {
      await logoutUser();
      onSessionChange(null);
      setSuccessMsg('Session successfully terminated');
      setTimeout(() => {
        onClose();
      }, 700);
    } catch (err: any) {
      setError(err.message || 'Logout failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-slate-900/50 backdrop-blur-xs z-50 flex items-center justify-center p-4">
      <div className="bg-white border border-slate-200 w-full max-w-xl rounded-2xl shadow-2xl overflow-hidden font-sans">
        {/* Header */}
        <div className="p-5 sm:p-6 border-b border-slate-100 bg-white flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-blue-50 text-blue-600 flex items-center justify-center flex-shrink-0">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-slate-900">
                SOC Operator Identity & Sign In
              </h3>
              <p className="text-xs text-slate-500 mt-0.5">
                Sign in with your email or Gmail to set your operator identity across investigations
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition-colors cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="p-6 space-y-6 max-h-[85vh] overflow-y-auto">
          {/* Current Active Session Status */}
          <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2">
            <div className="text-[11px] text-slate-500 font-semibold uppercase tracking-wider">
              Current Active Operator
            </div>
            {currentUser ? (
              <div className="flex flex-wrap items-center justify-between gap-3 pt-0.5">
                <div>
                  <div className="text-sm font-bold text-slate-900 flex items-center gap-2">
                    <span>{currentUser.name}</span>
                    <span
                      className={`px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase ${
                        currentUser.role === 'ADMIN'
                          ? 'bg-red-50 text-red-700 border border-red-200'
                          : currentUser.role === 'AUDITOR'
                          ? 'bg-amber-50 text-amber-700 border border-amber-200'
                          : 'bg-blue-50 text-blue-700 border border-blue-200'
                      }`}
                    >
                      {currentUser.role}
                    </span>
                  </div>
                  <div className="text-xs text-slate-500 font-mono mt-0.5">
                    {currentUser.email} • Badge {currentUser.badgeNumber}
                  </div>
                </div>

                <button
                  onClick={handleLogout}
                  disabled={loading}
                  className="px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-red-50 hover:bg-red-100 text-red-700 border border-red-200 flex items-center gap-1.5 transition-colors cursor-pointer disabled:opacity-50"
                  title="Sign out of current operator session"
                >
                  <LogOut className="w-3.5 h-3.5" />
                  <span>Logout</span>
                </button>
              </div>
            ) : (
              <div className="flex items-center gap-2 text-amber-700 text-xs py-1">
                <AlertCircle className="w-4 h-4 text-amber-600 flex-shrink-0" />
                <span>No active operator session. Please sign in below to set your operator identity.</span>
              </div>
            )}
          </div>

          {/* Feedback messages */}
          {error && (
            <div className="p-3 rounded-lg bg-red-50 border border-red-200 text-red-800 text-xs flex items-center gap-2">
              <AlertCircle className="w-4 h-4 text-red-600 flex-shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {successMsg && (
            <div className="p-3 rounded-lg bg-emerald-50 border border-emerald-200 text-emerald-800 text-xs flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-600 flex-shrink-0" />
              <span>{successMsg}</span>
            </div>
          )}

          {/* Operator Sign In / Registration Form */}
          <form onSubmit={handleCustomLogin} className="space-y-4 pt-1">
            <div className="flex items-center justify-between">
              <div className="text-xs font-bold text-slate-800 uppercase tracking-wide flex items-center gap-1.5">
                <UserCheck className="w-4 h-4 text-blue-600" />
                <span>Sign In with Your Gmail / Email</span>
              </div>
              <span className="text-[11px] text-slate-400">Custom Operator Profile</span>
            </div>

            <div className="space-y-3">
              <div>
                <label className="text-xs text-slate-600 font-medium block mb-1">
                  Your Full Name
                </label>
                <input
                  type="text"
                  placeholder="e.g. Vignesh or Alex Rivera"
                  value={nameInput}
                  onChange={e => setNameInput(e.target.value)}
                  className="w-full bg-slate-50 border border-slate-200 rounded-lg px-3.5 py-2 text-xs text-slate-800 placeholder:text-slate-400 focus:outline-none focus:border-blue-500 focus:bg-white"
                />
                <p className="text-[10px] text-slate-400 mt-0.5">
                  The name you provide here will appear as the active operator and be signed onto case evidence.
                </p>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="text-xs text-slate-600 font-medium block mb-1">
                    Email / Gmail Address <span className="text-red-500">*</span>
                  </label>
                  <input
                    type="email"
                    required
                    placeholder="user@gmail.com"
                    value={emailInput}
                    onChange={e => setEmailInput(e.target.value)}
                    className="w-full bg-slate-50 border border-slate-200 rounded-lg px-3.5 py-2 text-xs text-slate-800 placeholder:text-slate-400 focus:outline-none focus:border-blue-500 focus:bg-white"
                  />
                </div>
                <div>
                  <label className="text-xs text-slate-600 font-medium block mb-1">
                    Password / Passphrase <span className="text-red-500">*</span>
                  </label>
                  <input
                    type="password"
                    required
                    placeholder="••••••••••••"
                    value={passwordInput}
                    onChange={e => setPasswordInput(e.target.value)}
                    className="w-full bg-slate-50 border border-slate-200 rounded-lg px-3.5 py-2 text-xs text-slate-800 placeholder:text-slate-400 focus:outline-none focus:border-blue-500 focus:bg-white"
                  />
                </div>
              </div>

              <div>
                <label className="text-xs text-slate-600 font-medium block mb-1">
                  Operator Role
                </label>
                <select
                  value={roleInput}
                  onChange={e => setRoleInput(e.target.value as any)}
                  className="w-full bg-slate-50 border border-slate-200 rounded-lg px-3 py-2 text-xs text-slate-800 focus:outline-none focus:border-blue-500 focus:bg-white cursor-pointer"
                >
                  <option value="ANALYST">SOC Analyst (Incident responder, evidence verification)</option>
                  <option value="SENIOR_ANALYST">Senior SOC Analyst (Collaborative case assignment)</option>
                  <option value="ADMIN">SOC Security Administrator (Full supervisory control)</option>
                  <option value="AUDITOR">Compliance Auditor (Read-only forensic inspection)</option>
                </select>
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full py-2.5 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-xs font-semibold shadow-xs transition-colors cursor-pointer disabled:opacity-50 mt-1 flex items-center justify-center gap-1.5"
            >
              <Lock className="w-3.5 h-3.5" />
              <span>{loading ? 'Authenticating...' : 'Sign In as Active Operator'}</span>
            </button>
          </form>

          {/* Quick Operator Switcher (Demonstrating Multi-User RBAC & Cross-User Isolation) */}
          <div className="pt-4 border-t border-slate-100 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-slate-800 uppercase tracking-wide">
                Simulated Test Personas (1-Click Switch)
              </span>
              <span className="text-[11px] text-slate-500 font-medium">Quick RBAC Testing</span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
              {PRESET_OPERATORS.map(op => {
                const isActive = currentUser?.email === op.email;
                return (
                  <button
                    key={op.email}
                    onClick={() => handleQuickSwitch(op)}
                    disabled={loading || isActive}
                    className={`text-left p-3 rounded-xl border transition-all cursor-pointer ${
                      isActive
                        ? 'bg-blue-50/70 border-blue-300 ring-1 ring-blue-300'
                        : 'bg-slate-50/80 border-slate-200 hover:border-slate-300 hover:bg-slate-100/70'
                    } disabled:opacity-60`}
                  >
                    <div className="flex items-center justify-between gap-1">
                      <span className="text-xs font-bold text-slate-900 truncate">{op.name.split(' ')[0]}</span>
                      <span
                        className={`px-1.5 py-0.2 rounded-full text-[9px] font-bold uppercase ${
                          op.role === 'ADMIN'
                            ? 'bg-red-50 text-red-700 border border-red-200'
                            : 'bg-blue-50 text-blue-700 border border-blue-200'
                        }`}
                      >
                        {op.role}
                      </span>
                    </div>
                    <div className="text-[10px] text-slate-500 font-mono mt-1 truncate">{op.email}</div>
                  </button>
                );
              })}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
