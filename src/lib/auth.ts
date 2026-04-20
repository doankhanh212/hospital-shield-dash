/** Token storage and auth utilities. */

const TOKEN_KEY = 'hqg_access_token';
const USER_KEY  = 'hqg_user';

export interface AuthUser {
  username: string;
  role: 'admin' | 'analyst';
}

export const authStorage = {
  getToken: (): string | null => localStorage.getItem(TOKEN_KEY),
  setToken: (token: string) => localStorage.setItem(TOKEN_KEY, token),
  getUser:  (): AuthUser | null => {
    const raw = localStorage.getItem(USER_KEY);
    return raw ? (JSON.parse(raw) as AuthUser) : null;
  },
  setUser:  (user: AuthUser) => localStorage.setItem(USER_KEY, JSON.stringify(user)),
  clear:    () => { localStorage.removeItem(TOKEN_KEY); localStorage.removeItem(USER_KEY); },
  isLoggedIn: (): boolean => !!localStorage.getItem(TOKEN_KEY),
};
