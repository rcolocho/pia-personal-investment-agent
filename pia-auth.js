/**
 * pia-auth.js — PIA Supabase Auth Library
 * ─────────────────────────────────────────────────────────────────
 * Stage 2 auth for Personal Investment Agent.
 * Ported from portal-auth.js (Solenetec) — scoped to PIA only.
 *
 * Handles:
 *   - Supabase client init + session management
 *   - Email + password sign-in
 *   - TOTP MFA enrollment and verification
 *   - Multi-device session handling
 *   - Route guards (redirect to login if no session)
 *   - JWT retrieval for Worker API calls
 *   - Password reset + magic link flows
 *   - Sign out
 *
 * Usage in each PIA page:
 *   <script src="pia-auth.js"></script>
 *   <script>PIAAuth.init({ page: 'dashboard' });</script>
 *
 * Pages: 'login' | 'dashboard' | 'enroll'
 */

const PIA_SUPABASE_URL     = 'YOUR_SUPABASE_URL';
const PIA_SUPABASE_ANON_KEY = 'YOUR_SUPABASE_ANON_KEY';
const PIA_WORKER_URL        = 'YOUR_CLOUDFLARE_WORKER_URL';

// ── Load Supabase SDK from CDN ────────────────────────────────────
(function loadSupabaseSDK() {
  if (window.supabase) return;
  const script   = document.createElement('script');
  script.src     = 'https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2/dist/umd/supabase.min.js';
  script.onload  = () => {
    window._supabaseReady = true;
    document.dispatchEvent(new Event('pia:supabase:ready'));
  };
  script.onerror = () => console.error('[PIAAuth] Failed to load Supabase SDK');
  document.head.appendChild(script);
})();

function waitForSupabase(cb) {
  if (window._supabaseReady && window.supabase) return cb();
  document.addEventListener('pia:supabase:ready', cb, { once: true });
}

// ── PIAAuth public API ────────────────────────────────────────────
window.PIAAuth = {
  _client:  null,
  _session: null,

  /**
   * init({ page })
   * Call once per page after DOM is ready.
   * page: 'login' | 'dashboard' | 'enroll'
   */
  async init({ page = 'dashboard' } = {}) {
    await new Promise(resolve => waitForSupabase(resolve));

    this._client = window.supabase.createClient(PIA_SUPABASE_URL, PIA_SUPABASE_ANON_KEY, {
      auth: {
        persistSession:     true,
        autoRefreshToken:   true,
        detectSessionInUrl: true,   // handles magic-link + invite tokens in URL hash
        storageKey:         'pia_portal_session',
      }
    });

    // Auth state listener
    this._client.auth.onAuthStateChange(async (event, session) => {
      this._session = session;

      if (event === 'SIGNED_IN' || event === 'TOKEN_REFRESHED') {
        if (page === 'login') {
          // Check MFA before redirecting to dashboard
          const mfaStatus = await this.getMFAStatus();
          if (mfaStatus.enrolled && !mfaStatus.verified) {
            // Has MFA enrolled but not yet verified this session → stay on login, show TOTP prompt
            document.dispatchEvent(new CustomEvent('pia:mfa:required'));
          } else {
            window.location.href = '/pia-dashboard';
          }
        }
      }

      if (event === 'SIGNED_OUT') {
        if (page !== 'login') window.location.href = '/pia-login';
      }

      if (event === 'PASSWORD_RECOVERY') {
        if (page === 'login') {
          document.dispatchEvent(new CustomEvent('pia:password:recovery'));
        }
      }

      if (event === 'USER_UPDATED') {
        document.dispatchEvent(new CustomEvent('pia:user:updated', { detail: session }));
      }
    });

    // Get current session
    const { data: { session } } = await this._client.auth.getSession();
    this._session = session;

    // Route guard — non-login pages require a valid session
    if (!session && page !== 'login') {
      window.location.href = '/pia-login';
      return null;
    }

    // Dashboard: verify MFA if enrolled
    if (page === 'dashboard' && session) {
      const mfaStatus = await this.getMFAStatus();
      if (mfaStatus.enrolled && !mfaStatus.verified) {
        // MFA enrolled but not verified this session → kick back to login
        await this._client.auth.signOut();
        window.location.href = '/pia-login?mfa=required';
        return null;
      }
    }

    return session;
  },

  // ── Get JWT for Worker API calls ────────────────────────────────
  // Use this wherever authHeaders() was used in Stage 1:
  //   const token = await PIAAuth.getToken();
  //   headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' }
  async getToken() {
    const { data: { session } } = await this._client.auth.getSession();
    return session?.access_token || null;
  },

  // ── Auth headers helper (drop-in for Stage 1 authHeaders()) ─────
  async authHeaders(extra = {}) {
    const token = await this.getToken();
    if (!token) throw new Error('Not authenticated');
    return {
      'Content-Type':  'application/json',
      'Authorization': `Bearer ${token}`,
      ...extra
    };
  },

  // ── Sign in with email + password ───────────────────────────────
  async signIn(email, password) {
    const { data, error } = await this._client.auth.signInWithPassword({ email, password });
    if (error) throw error;

    // Check if MFA is required
    const factors = data.user?.factors || [];
    const hasTOTP  = factors.some(f => f.factor_type === 'totp' && f.status === 'verified');
    return { session: data.session, requires_mfa: hasTOTP };
  },

  // ── MFA: get current status ─────────────────────────────────────
  async getMFAStatus() {
    try {
      const { data } = await this._client.auth.mfa.getAuthenticatorAssuranceLevel();
      return {
        enrolled: data?.nextLevel === 'aal2' || data?.currentLevel === 'aal2',
        verified: data?.currentLevel === 'aal2',
        currentLevel: data?.currentLevel,
        nextLevel:    data?.nextLevel,
      };
    } catch {
      return { enrolled: false, verified: false };
    }
  },

  // ── MFA: list enrolled factors ──────────────────────────────────
  async listFactors() {
    const { data, error } = await this._client.auth.mfa.listFactors();
    if (error) throw error;
    return data;
  },

  // ── MFA: start TOTP enrollment (returns QR code + secret) ───────
  async enrollTOTP() {
    const { data, error } = await this._client.auth.mfa.enroll({
      factorType: 'totp',
      friendlyName: 'PIA Authenticator',
    });
    if (error) throw error;
    // data.totp.qr_code  — SVG string to render as QR code
    // data.totp.secret   — manual entry fallback
    // data.id            — factorId needed for challenge/verify
    return data;
  },

  // ── MFA: send challenge (call before verifying) ──────────────────
  async challengeTOTP(factorId) {
    const { data, error } = await this._client.auth.mfa.challenge({ factorId });
    if (error) throw error;
    return data; // data.id = challengeId
  },

  // ── MFA: verify TOTP code ────────────────────────────────────────
  async verifyTOTP(factorId, challengeId, code) {
    const { data, error } = await this._client.auth.mfa.verify({
      factorId,
      challengeId,
      code: code.replace(/\s/g, ''), // strip spaces
    });
    if (error) throw error;
    return data;
  },

  // ── MFA: challenge + verify in one step (for login flow) ─────────
  async challengeAndVerify(code) {
    const factors = await this.listFactors();
    const totp    = factors?.totp?.[0];
    if (!totp) throw new Error('No TOTP factor enrolled');

    const challenge = await this.challengeTOTP(totp.id);
    return await this.verifyTOTP(totp.id, challenge.id, code);
  },

  // ── MFA: unenroll a factor ───────────────────────────────────────
  async unenrollFactor(factorId) {
    const { error } = await this._client.auth.mfa.unenroll({ factorId });
    if (error) throw error;
  },

  // ── Send magic link (existing users only) ────────────────────────
  async sendMagicLink(email) {
    const { error } = await this._client.auth.signInWithOtp({
      email,
      options: {
        emailRedirectTo:  `${window.location.origin}/pia-dashboard`,
        shouldCreateUser: false, // no self-signup
      }
    });
    if (error) throw error;
  },

  // ── Send password reset email ────────────────────────────────────
  async sendPasswordReset(email) {
    const { error } = await this._client.auth.resetPasswordForEmail(email, {
      redirectTo: `${window.location.origin}/pia-login`,
    });
    if (error) throw error;
  },

  // ── Get current user profile ─────────────────────────────────────
  async getProfile() {
    const { data, error } = await this._client
      .from('pia_users')
      .select('*')
      .single();
    if (error) throw error;
    return data;
  },

  // ── Update user profile ──────────────────────────────────────────
  async updateProfile(updates) {
    const { error } = await this._client
      .from('pia_users')
      .update({ ...updates, updated_at: new Date().toISOString() })
      .eq('id', this._session?.user?.id);
    if (error) throw error;
  },

  // ── Get current user ─────────────────────────────────────────────
  getUser() {
    return this._session?.user || null;
  },

  // ── Sign out ─────────────────────────────────────────────────────
  async signOut() {
    await this._client.auth.signOut();
    // onAuthStateChange SIGNED_OUT will handle redirect
  },
};
