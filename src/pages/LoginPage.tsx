import { useState, FormEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Eye, EyeOff, AlertCircle, Loader2 } from 'lucide-react';
import { api } from '@/lib/api';
import { authStorage } from '@/lib/auth';

const LoginPage = () => {
  const navigate = useNavigate();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPw, setShowPw] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!username.trim() || !password.trim()) {
      setError('Vui lòng nhập tên đăng nhập và mật khẩu.');
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const res = await api.login(username.trim(), password);
      authStorage.setToken(res.access_token);
      const user = await api.me();
      authStorage.setUser(user);
      navigate('/', { replace: true });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.detail ?? err.message : String(err);
      // Try to extract FastAPI detail from JSON error
      let detail = msg;
      try {
        const parsed = JSON.parse(msg.replace(/^.*?(\{)/, '{'));
        detail = parsed.detail ?? msg;
      } catch { /* not json */ }
      setError(detail === 'Incorrect username or password'
        ? 'Tên đăng nhập hoặc mật khẩu không đúng.'
        : detail);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-background px-4">
      <div className="w-full max-w-sm space-y-8">
        {/* Logo */}
        <div className="text-center">
          <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-primary/10 mb-4">
            <Shield size={30} className="text-primary" />
          </div>
          <h1 className="text-2xl font-bold text-foreground">HQG Security</h1>
          <p className="mt-1 text-sm text-muted-foreground">Hospital Shield Platform</p>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="rounded-xl border border-border bg-card p-6 space-y-4 shadow-sm">
          <div>
            <label className="block text-xs font-medium text-foreground mb-1.5">
              Tên đăng nhập
            </label>
            <input
              type="text"
              autoComplete="username"
              value={username}
              onChange={e => setUsername(e.target.value)}
              disabled={loading}
              className="w-full rounded-lg border border-border bg-background px-3 py-2.5 text-sm text-foreground placeholder:text-muted-foreground focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary/30 transition-colors disabled:opacity-50"
              placeholder="admin"
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-foreground mb-1.5">
              Mật khẩu
            </label>
            <div className="relative">
              <input
                type={showPw ? 'text' : 'password'}
                autoComplete="current-password"
                value={password}
                onChange={e => setPassword(e.target.value)}
                disabled={loading}
                className="w-full rounded-lg border border-border bg-background px-3 py-2.5 pr-10 text-sm text-foreground placeholder:text-muted-foreground focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary/30 transition-colors disabled:opacity-50"
                placeholder="••••••••"
              />
              <button
                type="button"
                onClick={() => setShowPw(v => !v)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                tabIndex={-1}
              >
                {showPw ? <EyeOff size={15} /> : <Eye size={15} />}
              </button>
            </div>
          </div>

          {error && (
            <div className="flex items-center gap-2 rounded-lg bg-destructive/10 border border-destructive/20 px-3 py-2.5 text-xs text-destructive">
              <AlertCircle size={14} className="shrink-0" />
              <span>{error}</span>
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full flex items-center justify-center gap-2 rounded-lg bg-primary px-4 py-2.5 text-sm font-semibold text-primary-foreground hover:bg-primary/90 transition-colors disabled:opacity-60 shadow-sm"
          >
            {loading ? <Loader2 size={15} className="animate-spin" /> : null}
            {loading ? 'Đang đăng nhập...' : 'Đăng nhập'}
          </button>

          <p className="text-center text-[11px] text-muted-foreground">
            Liên hệ quản trị viên nếu quên mật khẩu
          </p>
        </form>
      </div>
    </div>
  );
};

export default LoginPage;

// Extend Error to carry FastAPI detail field
declare global {
  interface Error {
    detail?: string;
  }
}
