import React, { useState } from 'react';
import {
  ShieldCheck,
  Lock,
  Mail,
  User,
  Eye,
  EyeOff,
  ArrowRight,
  CheckCircle2,
  AlertCircle,
  KeyRound,
  ShieldAlert,
  Sparkles,
  RefreshCw,
  Check,
  X,
} from 'lucide-react';
import {
  loginUser,
  registerUser,
  requestPasswordReset,
  resetPassword,
  verifyEmail,
  UserSessionProfile,
} from '../services/api';
import { supabase, isSupabaseConfigured } from '../services/supabase';

export type AuthScreen =
  | 'login'
  | 'signup'
  | 'forgot-password'
  | 'reset-password'
  | 'verify-email';

interface AuthPageProps {
  onAuthenticated: (user: UserSessionProfile) => void;
  initialScreen?: AuthScreen;
}

export const AuthPage: React.FC<AuthPageProps> = ({
  onAuthenticated,
  initialScreen = 'login',
}) => {
  const [screen, setScreen] = useState<AuthScreen>(initialScreen);

  // Form Fields
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [role, setRole] = useState<'ANALYST' | 'SENIOR_ANALYST' | 'ADMIN' | 'AUDITOR'>('ANALYST');
  const [rememberMe, setRememberMe] = useState(true);
  const [resetTokenOrCode, setResetTokenOrCode] = useState('');
  const [verificationCode, setVerificationCode] = useState('');

  // UI States
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  // Automatically check if user returned from Supabase email confirmation link
  React.useEffect(() => {
    if (!isSupabaseConfigured || !supabase) return;
    supabase.auth.getSession().then(({ data }) => {
      if (data.session?.user) {
        const sbUser = data.session.user;
        const profile: UserSessionProfile = {
          userId: sbUser.id,
          email: sbUser.email || '',
          name: sbUser.user_metadata?.full_name || sbUser.email?.split('@')[0] || 'SOC Operator',
          role: (sbUser.user_metadata?.role as any) || 'ANALYST',
          organization: 'CyberTrace SOC Operations',
          badgeNumber: `SOC-${sbUser.id.slice(0, 4)}`,
        };
        onAuthenticated(profile);
      }
    });
  }, [onAuthenticated]);

  // Clear messages when switching screens
  const switchScreen = (newScreen: AuthScreen) => {
    setScreen(newScreen);
    setError(null);
    setFieldErrors({});
    setSuccessMessage(null);
  };

  // Password Strength Evaluation
  const evaluatePasswordStrength = (pass: string) => {
    let score = 0;
    if (pass.length >= 8) score++;
    if (/[A-Z]/.test(pass)) score++;
    if (/[a-z]/.test(pass)) score++;
    if (/[0-9]/.test(pass)) score++;
    if (/[^A-Za-z0-9]/.test(pass)) score++;
    return score;
  };
  const passwordScore = evaluatePasswordStrength(password);

  // Client-Side Validation Helpers
  const validateEmail = (val: string): boolean => {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(val.trim());
  };

  // Handle Login Submission
  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setFieldErrors({});
    setSuccessMessage(null);

    const errors: Record<string, string> = {};
    if (!email.trim()) errors.email = 'Email address is required';
    else if (!validateEmail(email)) errors.email = 'Please provide a valid email format';

    if (!password) errors.password = 'Password is required';

    if (Object.keys(errors).length > 0) {
      setFieldErrors(errors);
      return;
    }

    setLoading(true);
    try {
      // 1. If Supabase configured, attempt Supabase Auth first
      if (isSupabaseConfigured && supabase) {
        const { data, error: sbError } = await supabase.auth.signInWithPassword({
          email: email.trim(),
          password,
        });
        if (sbError) {
          if (sbError.message?.toLowerCase().includes('email not confirmed')) {
            setError(
              'Email not confirmed. Supabase requires email verification for this account before sign-in.'
            );
            return;
          }
          throw new Error(sbError.message);
        }
        if (data.user) {
          // Fetch user profile from public.profiles
          const { data: profileData } = await supabase
            .from('profiles')
            .select('*')
            .eq('id', data.user.id)
            .single();

          const profile: UserSessionProfile = {
            userId: data.user.id,
            email: data.user.email || email.trim(),
            name: profileData?.full_name || data.user.user_metadata?.full_name || 'SOC Analyst',
            role: profileData?.role || data.user.user_metadata?.role || 'ANALYST',
            organization: profileData?.organization || 'CyberTrace SOC Operations',
            badgeNumber: profileData?.badge_number || `SOC-${data.user.id.slice(0, 4)}`,
          };
          onAuthenticated(profile);
          return;
        }
      }

      // 2. Standard Enterprise Backend Auth
      const { user } = await loginUser(email.trim(), password, undefined, undefined, rememberMe);
      setSuccessMessage(`Welcome back, ${user.name}!`);
      setTimeout(() => {
        onAuthenticated(user);
      }, 500);
    } catch (err: any) {
      setError(err?.message || 'Invalid email address or password. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  // Helper: Resend Supabase verification email
  const handleResendConfirmation = async (targetEmail = email) => {
    if (!isSupabaseConfigured || !supabase || !targetEmail.trim()) {
      setError('Please provide an email address to resend confirmation.');
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const { error: resendErr } = await supabase.auth.resend({
        type: 'signup',
        email: targetEmail.trim(),
        options: {
          emailRedirectTo: `${window.location.origin}/`,
        },
      });
      if (resendErr) {
        if (resendErr.message?.toLowerCase().includes('rate limit')) {
          setError(
            'Supabase email rate limit reached (free tier limit of 3 emails/hour). If you own this Supabase project, you can turn off "Confirm email" under Authentication → Providers → Email in your Supabase dashboard to sign in immediately.'
          );
        } else {
          setError(resendErr.message);
        }
      } else {
        setSuccessMessage(`Confirmation link resent to ${targetEmail.trim()}. Please check your email inbox.`);
      }
    } catch (err: any) {
      setError(err?.message || 'Failed to resend confirmation email.');
    } finally {
      setLoading(false);
    }
  };

  // Helper: One-click Demo Operator login
  const handleDemoSignIn = async (rolePreset: 'ANALYST' | 'ADMIN' = 'ANALYST') => {
    setLoading(true);
    setError(null);
    try {
      const demoEmail = rolePreset === 'ADMIN' ? 'admin@soc.internal' : 'analyst@soc.internal';
      const demoPass = rolePreset === 'ADMIN' ? 'Admin@SOC2026!' : 'Analyst@SOC2026!';
      const { user } = await loginUser(demoEmail, demoPass);
      setSuccessMessage(`Authenticated as ${user.name} (${user.role})`);
      setTimeout(() => onAuthenticated(user), 400);
    } catch (err: any) {
      setError(err?.message || 'Failed to initialize demo operator session.');
    } finally {
      setLoading(false);
    }
  };

  // Handle Sign-Up Submission
  const handleSignUp = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setFieldErrors({});
    setSuccessMessage(null);

    const errors: Record<string, string> = {};
    if (!name.trim()) errors.name = 'Full name or username is required';
    else if (name.trim().length < 2) errors.name = 'Name must be at least 2 characters';

    if (!email.trim()) errors.email = 'Email address is required';
    else if (!validateEmail(email)) errors.email = 'Please provide a valid email format';

    if (!password) {
      errors.password = 'Password is required';
    } else if (password.length < 8) {
      errors.password = 'Password must be at least 8 characters';
    } else if (passwordScore < 3) {
      errors.password = 'Password must contain uppercase, numbers, or special symbols';
    }

    if (password !== confirmPassword) {
      errors.confirmPassword = 'Passwords do not match';
    }

    if (Object.keys(errors).length > 0) {
      setFieldErrors(errors);
      return;
    }

    setLoading(true);
    try {
      // 1. If Supabase configured, attempt Supabase Auth sign-up
      if (isSupabaseConfigured && supabase) {
        const { data, error: sbError } = await supabase.auth.signUp({
          email: email.trim(),
          password,
          options: {
            emailRedirectTo: `${window.location.origin}/`,
            data: {
              full_name: name.trim(),
              role,
            },
          },
        });
        if (sbError) {
          if (sbError.message?.toLowerCase().includes('rate limit')) {
            throw new Error(
              'Supabase email rate limit reached (free tier limit of 3 emails/hour). If you already registered, please check your inbox or disable "Confirm email" in Supabase settings.'
            );
          }
          throw new Error(sbError.message);
        }
        if (data.user) {
          setSuccessMessage(
            data.session
              ? `Account created successfully! Welcome, ${name}.`
              : 'Account registered! Please check your email for the confirmation link.'
          );
          if (data.session) {
            const profile: UserSessionProfile = {
              userId: data.user.id,
              email: data.user.email || email.trim(),
              name: name.trim(),
              role,
              organization: 'CyberTrace SOC Operations',
              badgeNumber: `SOC-${data.user.id.slice(0, 4)}`,
            };
            setTimeout(() => onAuthenticated(profile), 600);
            return;
          } else {
            setScreen('verify-email');
            return;
          }
        }
      }

      // 2. Standard Enterprise Backend Registration
      const { user } = await registerUser(
        email.trim(),
        password,
        name.trim(),
        role,
        rememberMe
      );
      setSuccessMessage(`Account created successfully! Welcome to the SOC, ${user.name}.`);
      setTimeout(() => {
        onAuthenticated(user);
      }, 600);
    } catch (err: any) {
      setError(err?.message || 'Registration failed. Please check your information and try again.');
    } finally {
      setLoading(false);
    }
  };

  // Handle Forgot Password Request
  const handleForgotPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setFieldErrors({});

    if (!email.trim() || !validateEmail(email)) {
      setFieldErrors({ email: 'Please provide a valid registered email address' });
      return;
    }

    setLoading(true);
    try {
      if (isSupabaseConfigured && supabase) {
        const { error: sbError } = await supabase.auth.resetPasswordForEmail(email.trim(), {
          redirectTo: `${window.location.origin}/`,
        });
        if (sbError) throw new Error(sbError.message);
        setSuccessMessage('Password reset instructions sent. Please check your inbox.');
        setTimeout(() => setScreen('reset-password'), 1500);
        return;
      }

      const res = await requestPasswordReset(email.trim());
      setSuccessMessage(res.message);
      if (res.verificationCode) {
        setResetTokenOrCode(res.verificationCode);
      }
      setTimeout(() => setScreen('reset-password'), 1200);
    } catch (err: any) {
      setError(err?.message || 'Failed to dispatch password reset request.');
    } finally {
      setLoading(false);
    }
  };

  // Handle Reset Password Submission
  const handleResetPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setFieldErrors({});

    const errors: Record<string, string> = {};
    if (!resetTokenOrCode.trim()) errors.token = 'Reset verification code or token is required';
    if (!password || password.length < 8) errors.password = 'New password must be at least 8 characters';
    if (password !== confirmPassword) errors.confirmPassword = 'Passwords do not match';

    if (Object.keys(errors).length > 0) {
      setFieldErrors(errors);
      return;
    }

    setLoading(true);
    try {
      if (isSupabaseConfigured && supabase) {
        const { error: sbError } = await supabase.auth.updateUser({ password });
        if (sbError) throw new Error(sbError.message);
        setSuccessMessage('Password updated successfully. You may now sign in.');
        setTimeout(() => setScreen('login'), 1200);
        return;
      }

      const res = await resetPassword(resetTokenOrCode.trim(), password);
      setSuccessMessage(res.message);
      setTimeout(() => setScreen('login'), 1200);
    } catch (err: any) {
      setError(err?.message || 'Password reset failed. Please ensure your code is valid.');
    } finally {
      setLoading(false);
    }
  };

  // Handle Email Verification Submission
  const handleVerifyEmail = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setFieldErrors({});

    if (!verificationCode.trim()) {
      setFieldErrors({ code: 'Please enter your 6-digit verification code' });
      return;
    }

    setLoading(true);
    try {
      const res = await verifyEmail(email.trim(), verificationCode.trim());
      setSuccessMessage('Email verified successfully! You may now sign in.');
      setTimeout(() => setScreen('login'), 1000);
    } catch (err: any) {
      setError(err?.message || 'Invalid or expired verification code.');
    } finally {
      setLoading(false);
    }
  };


  return (
    <div className="min-h-screen w-full bg-slate-950 flex items-center justify-center p-4 sm:p-6 lg:p-8 font-sans relative overflow-hidden select-none">
      {/* Background Ambience */}
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_80%_80%_at_50%_-20%,rgba(37,99,235,0.18),rgba(255,255,255,0))]" />
      <div className="absolute top-0 left-1/4 w-96 h-96 bg-blue-600/10 rounded-full blur-3xl pointer-events-none" />
      <div className="absolute bottom-0 right-1/4 w-96 h-96 bg-emerald-600/10 rounded-full blur-3xl pointer-events-none" />

      {/* Main Container */}
      <div className="w-full max-w-md relative z-10">
        {/* Brand Header */}
        <div className="text-center mb-6 sm:mb-8 space-y-2">
          <div className="inline-flex items-center gap-2.5 px-3.5 py-1.5 rounded-full bg-slate-900 border border-slate-800 shadow-inner">
            <ShieldCheck className="w-4 h-4 text-blue-500" />
            <span className="text-xs font-bold text-slate-200 tracking-wide">CyberTrace SOC Intelligence</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-bold text-white tracking-tight">
            AI Email Forensics Platform
          </h1>
          <p className="text-xs text-slate-400 max-w-xs mx-auto">
            Deterministic Header Forensics, RFC-822 Parsing & Blockchain Evidence Verification
          </p>
        </div>

        {/* Auth Card */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 sm:p-8 shadow-2xl backdrop-blur-xl transition-all">
          {/* Feedback Banners */}
          {error && (
            <div className="mb-5 p-3.5 rounded-xl bg-red-950/60 border border-red-800/80 text-red-200 text-xs flex flex-col gap-2.5 animate-fadeIn">
              <div className="flex items-start gap-2.5">
                <AlertCircle className="w-4 h-4 text-red-400 flex-shrink-0 mt-0.5" />
                <div className="flex-1 leading-relaxed">{error}</div>
              </div>

              {error.toLowerCase().includes('email not confirmed') && (
                <div className="mt-1 pt-2.5 border-t border-red-800/50 space-y-2">
                  <p className="text-[11px] text-slate-300">
                    A confirmation link was previously sent to your email. Click below to resend the activation link or sign in directly with the demo account:
                  </p>
                  <div className="flex flex-wrap gap-2 pt-0.5">
                    <button
                      type="button"
                      onClick={() => handleResendConfirmation(email)}
                      disabled={loading}
                      className="px-2.5 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-medium text-[11px] transition-colors cursor-pointer flex items-center gap-1.5"
                    >
                      <Mail className="w-3 h-3" />
                      <span>Resend Activation Link</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => switchScreen('verify-email')}
                      className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-medium text-[11px] transition-colors cursor-pointer"
                    >
                      Verification Screen
                    </button>
                    <button
                      type="button"
                      onClick={() => handleDemoSignIn('ANALYST')}
                      className="px-2.5 py-1.5 rounded-lg bg-emerald-700 hover:bg-emerald-600 text-white font-medium text-[11px] transition-colors cursor-pointer"
                    >
                      Instant Demo Login
                    </button>
                  </div>
                  <div className="text-[10.5px] text-slate-400 bg-slate-900/80 p-2 rounded-lg border border-slate-800">
                    💡 <strong>Tip for Supabase Project Owner:</strong> In your Supabase Dashboard, go to <strong>Authentication → Providers → Email</strong> and toggle off <strong>"Confirm email"</strong>. This allows users to register and sign in immediately without email confirmation!
                  </div>
                </div>
              )}
            </div>
          )}

          {successMessage && (
            <div className="mb-5 p-3.5 rounded-xl bg-emerald-950/60 border border-emerald-800/80 text-emerald-200 text-xs flex items-start gap-2.5 animate-fadeIn">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0 mt-0.5" />
              <div className="flex-1 leading-relaxed">{successMessage}</div>
            </div>
          )}

          {/* SCREEN 1: LOGIN */}
          {screen === 'login' && (
            <div>
              <div className="mb-6">
                <h2 className="text-lg font-bold text-white tracking-tight">Sign In to SOC Console</h2>
                <p className="text-xs text-slate-400 mt-1">
                  Enter your credentials to access authenticated case records and threat hunting.
                </p>
              </div>

              <form onSubmit={handleLogin} className="space-y-4">
                <div>
                  <label className="text-xs font-semibold text-slate-300 block mb-1.5">
                    Email Address
                  </label>
                  <div className="relative">
                    <input
                      type="email"
                      required
                      placeholder="analyst@soc.internal or name@gmail.com"
                      value={email}
                      onChange={e => setEmail(e.target.value)}
                      className={`w-full bg-slate-950/80 border ${
                        fieldErrors.email ? 'border-red-500' : 'border-slate-800'
                      } rounded-xl px-3.5 py-2.5 pl-10 text-xs text-slate-100 placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 transition-all`}
                    />
                    <Mail className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
                  </div>
                  {fieldErrors.email && (
                    <p className="text-[11px] text-red-400 mt-1">{fieldErrors.email}</p>
                  )}
                </div>

                <div>
                  <div className="flex items-center justify-between mb-1.5">
                    <label className="text-xs font-semibold text-slate-300">
                      Password
                    </label>
                    <button
                      type="button"
                      onClick={() => switchScreen('forgot-password')}
                      className="text-[11px] text-blue-400 hover:text-blue-300 font-medium transition-colors cursor-pointer"
                    >
                      Forgot Password?
                    </button>
                  </div>
                  <div className="relative">
                    <input
                      type={showPassword ? 'text' : 'password'}
                      required
                      placeholder="••••••••••••"
                      value={password}
                      onChange={e => setPassword(e.target.value)}
                      className={`w-full bg-slate-950/80 border ${
                        fieldErrors.password ? 'border-red-500' : 'border-slate-800'
                      } rounded-xl px-3.5 py-2.5 pl-10 pr-10 text-xs text-slate-100 placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 transition-all`}
                    />
                    <Lock className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
                    <button
                      type="button"
                      onClick={() => setShowPassword(prev => !prev)}
                      className="p-1 text-slate-500 hover:text-slate-300 absolute right-2.5 top-1/2 -translate-y-1/2 transition-colors cursor-pointer"
                      title={showPassword ? 'Hide password' : 'Show password'}
                    >
                      {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </button>
                  </div>
                  {fieldErrors.password && (
                    <p className="text-[11px] text-red-400 mt-1">{fieldErrors.password}</p>
                  )}
                </div>

                <div className="flex items-center justify-between pt-1">
                  <label className="flex items-center gap-2 cursor-pointer select-none">
                    <input
                      type="checkbox"
                      checked={rememberMe}
                      onChange={e => setRememberMe(e.target.checked)}
                      className="w-3.5 h-3.5 rounded border-slate-700 bg-slate-950 text-blue-600 focus:ring-blue-500"
                    />
                    <span className="text-xs text-slate-400">Remember Me</span>
                  </label>
                </div>

                <button
                  type="submit"
                  disabled={loading}
                  className="w-full py-2.5 rounded-xl bg-blue-600 hover:bg-blue-500 text-white font-semibold text-xs transition-all shadow-md hover:shadow-blue-600/25 flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50 mt-2"
                >
                  {loading ? (
                    <>
                      <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                      <span>Authenticating...</span>
                    </>
                  ) : (
                    <>
                      <span>Sign In</span>
                      <ArrowRight className="w-3.5 h-3.5" />
                    </>
                  )}
                </button>
              </form>

              <div className="mt-6 pt-5 border-t border-slate-800 text-center">
                <p className="text-xs text-slate-400">
                  Don't have an operator account?{' '}
                  <button
                    onClick={() => switchScreen('signup')}
                    className="text-blue-400 hover:text-blue-300 font-semibold transition-colors cursor-pointer"
                  >
                    Create Account
                  </button>
                </p>
              </div>
            </div>
          )}

          {/* SCREEN 2: SIGN UP */}
          {screen === 'signup' && (
            <div>
              <div className="mb-6">
                <h2 className="text-lg font-bold text-white tracking-tight">Create Operator Account</h2>
                <p className="text-xs text-slate-400 mt-1">
                  Join the CyberTrace SOC team. All forensic actions are sealed in the immutable evidence ledger.
                </p>
              </div>

              <form onSubmit={handleSignUp} className="space-y-4">
                <div>
                  <label className="text-xs font-semibold text-slate-300 block mb-1.5">
                    Full Name or Call-Sign
                  </label>
                  <div className="relative">
                    <input
                      type="text"
                      required
                      placeholder="e.g. Maya Chen or Alex Rivera"
                      value={name}
                      onChange={e => setName(e.target.value)}
                      className={`w-full bg-slate-950/80 border ${
                        fieldErrors.name ? 'border-red-500' : 'border-slate-800'
                      } rounded-xl px-3.5 py-2.5 pl-10 text-xs text-slate-100 placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 transition-all`}
                    />
                    <User className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
                  </div>
                  {fieldErrors.name && (
                    <p className="text-[11px] text-red-400 mt-1">{fieldErrors.name}</p>
                  )}
                </div>

                <div>
                  <label className="text-xs font-semibold text-slate-300 block mb-1.5">
                    Email Address
                  </label>
                  <div className="relative">
                    <input
                      type="email"
                      required
                      placeholder="analyst@domain.com or user@gmail.com"
                      value={email}
                      onChange={e => setEmail(e.target.value)}
                      className={`w-full bg-slate-950/80 border ${
                        fieldErrors.email ? 'border-red-500' : 'border-slate-800'
                      } rounded-xl px-3.5 py-2.5 pl-10 text-xs text-slate-100 placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 transition-all`}
                    />
                    <Mail className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
                  </div>
                  {fieldErrors.email && (
                    <p className="text-[11px] text-red-400 mt-1">{fieldErrors.email}</p>
                  )}
                </div>

                <div>
                  <label className="text-xs font-semibold text-slate-300 block mb-1.5">
                    Operational Role
                  </label>
                  <select
                    value={role}
                    onChange={e => setRole(e.target.value as any)}
                    className="w-full bg-slate-950/80 border border-slate-800 rounded-xl px-3.5 py-2.5 text-xs text-slate-100 focus:outline-none focus:ring-2 focus:ring-blue-500 transition-all cursor-pointer"
                  >
                    <option value="ANALYST">SOC Analyst (Incident Responder, Triage)</option>
                    <option value="SENIOR_ANALYST">Senior SOC Analyst (Case Assignment & Review)</option>
                    <option value="ADMIN">SOC Security Administrator (Full Oversight)</option>
                    <option value="AUDITOR">Compliance Auditor (Read-Only Forensic Audit)</option>
                  </select>
                </div>

                <div>
                  <label className="text-xs font-semibold text-slate-300 block mb-1.5">
                    Password
                  </label>
                  <div className="relative">
                    <input
                      type={showPassword ? 'text' : 'password'}
                      required
                      placeholder="Minimum 8 characters with numbers & symbols"
                      value={password}
                      onChange={e => setPassword(e.target.value)}
                      className={`w-full bg-slate-950/80 border ${
                        fieldErrors.password ? 'border-red-500' : 'border-slate-800'
                      } rounded-xl px-3.5 py-2.5 pl-10 pr-10 text-xs text-slate-100 placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 transition-all`}
                    />
                    <Lock className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
                    <button
                      type="button"
                      onClick={() => setShowPassword(prev => !prev)}
                      className="p-1 text-slate-500 hover:text-slate-300 absolute right-2.5 top-1/2 -translate-y-1/2 transition-colors cursor-pointer"
                    >
                      {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </button>
                  </div>
                  {/* Strength Bar */}
                  {password.length > 0 && (
                    <div className="mt-2 space-y-1">
                      <div className="flex gap-1 h-1">
                        {[1, 2, 3, 4, 5].map(lvl => (
                          <div
                            key={lvl}
                            className={`flex-1 rounded-full transition-all ${
                              passwordScore >= lvl
                                ? passwordScore <= 2
                                  ? 'bg-red-500'
                                  : passwordScore <= 3
                                  ? 'bg-amber-500'
                                  : 'bg-emerald-500'
                                : 'bg-slate-800'
                            }`}
                          />
                        ))}
                      </div>
                      <span className="text-[10px] text-slate-400">
                        {passwordScore <= 2 ? 'Weak' : passwordScore <= 3 ? 'Medium' : 'Strong'} password
                      </span>
                    </div>
                  )}
                  {fieldErrors.password && (
                    <p className="text-[11px] text-red-400 mt-1">{fieldErrors.password}</p>
                  )}
                </div>

                <div>
                  <label className="text-xs font-semibold text-slate-300 block mb-1.5">
                    Confirm Password
                  </label>
                  <div className="relative">
                    <input
                      type={showConfirmPassword ? 'text' : 'password'}
                      required
                      placeholder="Repeat your password"
                      value={confirmPassword}
                      onChange={e => setConfirmPassword(e.target.value)}
                      className={`w-full bg-slate-950/80 border ${
                        fieldErrors.confirmPassword ? 'border-red-500' : 'border-slate-800'
                      } rounded-xl px-3.5 py-2.5 pl-10 pr-10 text-xs text-slate-100 placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 transition-all`}
                    />
                    <KeyRound className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
                    <button
                      type="button"
                      onClick={() => setShowConfirmPassword(prev => !prev)}
                      className="p-1 text-slate-500 hover:text-slate-300 absolute right-2.5 top-1/2 -translate-y-1/2 transition-colors cursor-pointer"
                    >
                      {showConfirmPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </button>
                  </div>
                  {fieldErrors.confirmPassword && (
                    <p className="text-[11px] text-red-400 mt-1">{fieldErrors.confirmPassword}</p>
                  )}
                </div>

                <button
                  type="submit"
                  disabled={loading}
                  className="w-full py-2.5 rounded-xl bg-blue-600 hover:bg-blue-500 text-white font-semibold text-xs transition-all shadow-md hover:shadow-blue-600/25 flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50 mt-3"
                >
                  {loading ? (
                    <>
                      <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                      <span>Creating Account...</span>
                    </>
                  ) : (
                    <>
                      <span>Create Account</span>
                      <ArrowRight className="w-3.5 h-3.5" />
                    </>
                  )}
                </button>
              </form>

              <div className="mt-6 pt-5 border-t border-slate-800 text-center">
                <p className="text-xs text-slate-400">
                  Already have an operator account?{' '}
                  <button
                    onClick={() => switchScreen('login')}
                    className="text-blue-400 hover:text-blue-300 font-semibold transition-colors cursor-pointer"
                  >
                    Sign In
                  </button>
                </p>
              </div>
            </div>
          )}

          {/* SCREEN 3: FORGOT PASSWORD */}
          {screen === 'forgot-password' && (
            <div>
              <div className="mb-6">
                <h2 className="text-lg font-bold text-white tracking-tight">Reset Your Password</h2>
                <p className="text-xs text-slate-400 mt-1">
                  Enter your registered email address to receive password reset instructions and a verification code.
                </p>
              </div>

              <form onSubmit={handleForgotPassword} className="space-y-4">
                <div>
                  <label className="text-xs font-semibold text-slate-300 block mb-1.5">
                    Registered Email Address
                  </label>
                  <div className="relative">
                    <input
                      type="email"
                      required
                      placeholder="operator@soc.internal"
                      value={email}
                      onChange={e => setEmail(e.target.value)}
                      className={`w-full bg-slate-950/80 border ${
                        fieldErrors.email ? 'border-red-500' : 'border-slate-800'
                      } rounded-xl px-3.5 py-2.5 pl-10 text-xs text-slate-100 placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 transition-all`}
                    />
                    <Mail className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
                  </div>
                  {fieldErrors.email && (
                    <p className="text-[11px] text-red-400 mt-1">{fieldErrors.email}</p>
                  )}
                </div>

                <button
                  type="submit"
                  disabled={loading}
                  className="w-full py-2.5 rounded-xl bg-blue-600 hover:bg-blue-500 text-white font-semibold text-xs transition-all shadow-md hover:shadow-blue-600/25 flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50 mt-2"
                >
                  {loading ? (
                    <>
                      <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                      <span>Dispatching Instructions...</span>
                    </>
                  ) : (
                    <span>Send Reset Instructions</span>
                  )}
                </button>
              </form>

              <div className="mt-6 pt-5 border-t border-slate-800 text-center">
                <button
                  onClick={() => switchScreen('login')}
                  className="text-xs text-slate-400 hover:text-white transition-colors cursor-pointer"
                >
                  ← Return to Sign In
                </button>
              </div>
            </div>
          )}

          {/* SCREEN 4: RESET PASSWORD */}
          {screen === 'reset-password' && (
            <div>
              <div className="mb-6">
                <h2 className="text-lg font-bold text-white tracking-tight">Set New Password</h2>
                <p className="text-xs text-slate-400 mt-1">
                  Enter your reset verification code and choose a new secure password.
                </p>
              </div>

              <form onSubmit={handleResetPassword} className="space-y-4">
                <div>
                  <label className="text-xs font-semibold text-slate-300 block mb-1.5">
                    Reset Code / Token
                  </label>
                  <input
                    type="text"
                    required
                    placeholder="6-digit code or reset token"
                    value={resetTokenOrCode}
                    onChange={e => setResetTokenOrCode(e.target.value)}
                    className="w-full bg-slate-950/80 border border-slate-800 rounded-xl px-3.5 py-2.5 text-xs text-slate-100 placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 font-mono tracking-widest text-center"
                  />
                  {fieldErrors.token && (
                    <p className="text-[11px] text-red-400 mt-1">{fieldErrors.token}</p>
                  )}
                </div>

                <div>
                  <label className="text-xs font-semibold text-slate-300 block mb-1.5">
                    New Password
                  </label>
                  <div className="relative">
                    <input
                      type={showPassword ? 'text' : 'password'}
                      required
                      placeholder="Minimum 8 characters"
                      value={password}
                      onChange={e => setPassword(e.target.value)}
                      className="w-full bg-slate-950/80 border border-slate-800 rounded-xl px-3.5 py-2.5 pl-10 pr-10 text-xs text-slate-100 placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                    <Lock className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
                    <button
                      type="button"
                      onClick={() => setShowPassword(prev => !prev)}
                      className="p-1 text-slate-500 hover:text-slate-300 absolute right-2.5 top-1/2 -translate-y-1/2 transition-colors cursor-pointer"
                    >
                      {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </button>
                  </div>
                  {fieldErrors.password && (
                    <p className="text-[11px] text-red-400 mt-1">{fieldErrors.password}</p>
                  )}
                </div>

                <div>
                  <label className="text-xs font-semibold text-slate-300 block mb-1.5">
                    Confirm New Password
                  </label>
                  <div className="relative">
                    <input
                      type={showConfirmPassword ? 'text' : 'password'}
                      required
                      placeholder="Repeat your new password"
                      value={confirmPassword}
                      onChange={e => setConfirmPassword(e.target.value)}
                      className="w-full bg-slate-950/80 border border-slate-800 rounded-xl px-3.5 py-2.5 pl-10 pr-10 text-xs text-slate-100 placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                    <KeyRound className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
                    <button
                      type="button"
                      onClick={() => setShowConfirmPassword(prev => !prev)}
                      className="p-1 text-slate-500 hover:text-slate-300 absolute right-2.5 top-1/2 -translate-y-1/2 transition-colors cursor-pointer"
                    >
                      {showConfirmPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </button>
                  </div>
                  {fieldErrors.confirmPassword && (
                    <p className="text-[11px] text-red-400 mt-1">{fieldErrors.confirmPassword}</p>
                  )}
                </div>

                <button
                  type="submit"
                  disabled={loading}
                  className="w-full py-2.5 rounded-xl bg-blue-600 hover:bg-blue-500 text-white font-semibold text-xs transition-all shadow-md hover:shadow-blue-600/25 flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50 mt-2"
                >
                  {loading ? (
                    <>
                      <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                      <span>Updating Password...</span>
                    </>
                  ) : (
                    <span>Update Password</span>
                  )}
                </button>
              </form>

              <div className="mt-6 pt-5 border-t border-slate-800 text-center">
                <button
                  onClick={() => switchScreen('login')}
                  className="text-xs text-slate-400 hover:text-white transition-colors cursor-pointer"
                >
                  ← Return to Sign In
                </button>
              </div>
            </div>
          )}

          {/* SCREEN 5: EMAIL VERIFICATION */}
          {screen === 'verify-email' && (
            <div>
              <div className="mb-6 text-center">
                <div className="w-12 h-12 rounded-full bg-blue-600/20 text-blue-400 flex items-center justify-center mx-auto mb-3">
                  <Mail className="w-6 h-6" />
                </div>
                <h2 className="text-lg font-bold text-white tracking-tight">Confirm Your Email Address</h2>
                <p className="text-xs text-slate-400 mt-1">
                  We sent an activation email to <strong className="text-slate-200">{email}</strong>.
                </p>
              </div>

              {isSupabaseConfigured ? (
                <div className="space-y-4">
                  <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 text-center text-xs text-slate-300 space-y-2">
                    <p className="leading-relaxed">
                      Please check your inbox and click the <strong className="text-blue-400">"Confirm your email address"</strong> button in the email from Supabase.
                    </p>
                    <p className="text-[11px] text-slate-400">
                      Once confirmed, clicking the link in your email automatically logs you in!
                    </p>
                  </div>

                  <button
                    type="button"
                    onClick={async () => {
                      setLoading(true);
                      if (supabase) {
                        const { data } = await supabase.auth.getSession();
                        if (data.session?.user) {
                          const sbUser = data.session.user;
                          const profile: UserSessionProfile = {
                            userId: sbUser.id,
                            email: sbUser.email || '',
                            name: sbUser.user_metadata?.full_name || sbUser.email?.split('@')[0] || 'SOC Operator',
                            role: (sbUser.user_metadata?.role as any) || 'ANALYST',
                            organization: 'CyberTrace SOC Operations',
                            badgeNumber: `SOC-${sbUser.id.slice(0, 4)}`,
                          };
                          onAuthenticated(profile);
                          return;
                        }
                      }
                      setLoading(false);
                      switchScreen('login');
                    }}
                    disabled={loading}
                    className="w-full py-2.5 rounded-xl bg-blue-600 hover:bg-blue-500 text-white font-semibold text-xs transition-all shadow-md hover:shadow-blue-600/25 flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
                  >
                    {loading ? (
                      <>
                        <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                        <span>Checking Status...</span>
                      </>
                    ) : (
                      <span>I've Confirmed, Continue to Sign In</span>
                    )}
                  </button>

                  <div className="text-center pt-1 space-y-2.5">
                    <button
                      type="button"
                      onClick={() => handleResendConfirmation(email)}
                      disabled={loading}
                      className="text-xs text-blue-400 hover:text-blue-300 transition-colors cursor-pointer underline"
                    >
                      Resend confirmation email
                    </button>
                    <div className="text-[10.5px] text-slate-400 bg-slate-900/80 p-2.5 rounded-lg border border-slate-800 text-left">
                      💡 <strong>Supabase Dashboard Tip:</strong> To disable email verification and allow instant logins, visit <strong>Authentication → Providers → Email</strong> in your Supabase dashboard and toggle off <strong>"Confirm email"</strong>.
                    </div>
                  </div>
                </div>
              ) : (
                <form onSubmit={handleVerifyEmail} className="space-y-4">
                  <div>
                    <label className="text-xs font-semibold text-slate-300 block mb-1.5 text-center">
                      Enter 6-Digit Verification Code
                    </label>
                    <input
                      type="text"
                      required
                      maxLength={6}
                      placeholder="123456"
                      value={verificationCode}
                      onChange={e => setVerificationCode(e.target.value)}
                      className="w-full bg-slate-950/80 border border-slate-800 rounded-xl px-3.5 py-3 text-base text-slate-100 placeholder:text-slate-600 focus:outline-none focus:ring-2 focus:ring-blue-500 font-mono tracking-widest text-center"
                    />
                    {fieldErrors.code && (
                      <p className="text-[11px] text-red-400 mt-1 text-center">{fieldErrors.code}</p>
                    )}
                  </div>

                  <button
                    type="submit"
                    disabled={loading}
                    className="w-full py-2.5 rounded-xl bg-blue-600 hover:bg-blue-500 text-white font-semibold text-xs transition-all shadow-md hover:shadow-blue-600/25 flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50 mt-2"
                  >
                    {loading ? (
                      <>
                        <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                        <span>Verifying...</span>
                      </>
                    ) : (
                      <span>Confirm & Sign In</span>
                    )}
                  </button>
                </form>
              )}

              <div className="mt-6 pt-5 border-t border-slate-800 text-center">
                <button
                  onClick={() => switchScreen('login')}
                  className="text-xs text-slate-400 hover:text-white transition-colors cursor-pointer"
                >
                  ← Return to Sign In
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Security Footer Notice */}
        <div className="mt-6 text-center space-y-1 text-[11px] text-slate-500">
          <p>End-to-End Encrypted Session • SHA-256 Custody Ledger Active</p>
          <p className="text-[10px] text-slate-600">
            CyberTrace SOC Forensic Defense Platform • Strictly Authorized Personnel Only
          </p>
        </div>
      </div>
    </div>
  );
};
