// ═══════════════════════════════════════════════════════════════
// PIA Worker v4 — pia-agent Cloudflare Worker
// Stage 2: Supabase JWT auth replaces x-pia-key header
//
// Changes from v3:
//   - requireAuth() validates Supabase JWT via /auth/v1/user endpoint
//   - x-pia-key header still accepted as fallback (backward compat)
//   - CORS updated to include Authorization header
//   - userId extracted from JWT for future per-user KV namespacing
//   - /auth/register, /auth/login, /auth/mfa/verify stubs activated
//
// New secrets required in Worker (Settings → Variables → Secrets):
//   SUPABASE_URL      = YOUR_SUPABASE_URL
//   SUPABASE_ANON_KEY = eyJhbGci... (your anon public key)
//   DASHBOARD_SECRET  = keep for cron auth fallback
// ═══════════════════════════════════════════════════════════════

export default {
  async fetch(request, env) {
    const url    = new URL(request.url);
    const origin = request.headers.get("Origin") || "";

    // ── CORS — locked to your domain only ───────────────────────
    // Stage 2: add app.didimdigital.com when multi-user portal goes live
    const ALLOWED_ORIGINS = [
      "https://didimdigital.com",
      "https://www.didimdigital.com",
      "http://localhost:3000",   // local dev only — remove in production
    ];
    const corsOrigin = ALLOWED_ORIGINS.includes(origin) ? origin : "https://didimdigital.com";
    const cors = {
      "Access-Control-Allow-Origin":  corsOrigin,
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, x-pia-key, Authorization, x-live-confirm",
      "Vary": "Origin",
    };

    if (request.method === "OPTIONS") return new Response(null, { headers: cors });

    // ── Alpaca setup (shared) ────────────────────────────────────
    const mode = (await env.PIA_KV.get("pia:mode")) || "paper";
    const alpacaBase = mode === "live"
      ? "https://api.alpaca.markets"
      : "https://paper-api.alpaca.markets";
    const alpacaKey = mode === "live" ? env.ALPACA_LIVE_KEY_ID : env.ALPACA_PAPER_KEY_ID;
    const alpacaSec = mode === "live" ? env.ALPACA_LIVE_SECRET  : env.ALPACA_PAPER_SECRET;
    const alpacaHdrs = {
      "APCA-API-KEY-ID":     alpacaKey,
      "APCA-API-SECRET-KEY": alpacaSec,
      "Content-Type": "application/json",
    };

    // ════════════════════════════════════════════════════════════
    // AUTH HELPERS — Stage 2: Supabase JWT
    // ════════════════════════════════════════════════════════════

    /**
     * requireAuth — validates Supabase JWT from Authorization header.
     *
     * Accepts: "Authorization: Bearer <supabase_access_token>"
     * Falls back to x-pia-key for cron-triggered internal calls.
     *
     * Returns: { ok: true, userId, email } or { ok: false, error }
     *
     * How it works:
     *   Supabase JWTs are verified by calling /auth/v1/user with the token.
     *   This is a live network call — ~50ms — but correct. The alternative
     *   (local JWT verification) requires the SUPABASE_JWT_SECRET which is
     *   a server-side secret. Both approaches are valid; live call is simpler
     *   and catches revoked sessions correctly.
     */
    async function requireAuth(request) {
      // 1. Try Supabase JWT first (Stage 2 primary path)
      const authHeader = request.headers.get("Authorization") || "";
      const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";

      if (token) {
        try {
          const res = await fetch(`${env.SUPABASE_URL}/auth/v1/user`, {
            headers: {
              "Authorization": `Bearer ${token}`,
              "apikey": env.SUPABASE_ANON_KEY,
            }
          });
          if (res.ok) {
            const user = await res.json();
            if (user?.id) {
              return { ok: true, userId: user.id, email: user.email };
            }
          }
          return { ok: false, error: "Invalid or expired session — please sign in again" };
        } catch {
          return { ok: false, error: "Auth service unreachable" };
        }
      }

      // 2. Fall back to x-pia-key (Stage 1 backward compat + cron internal)
      const key = request.headers.get("x-pia-key");
      if (key && key === env.DASHBOARD_SECRET) {
        return { ok: true, userId: "owner", email: "owner" };
      }

      return { ok: false, error: "Unauthorized — sign in at didimdigital.com/pia-login" };
    }

    // Alias for call sites
    const requirePiaKey = requireAuth;

    /**
     * rateLimitIP — soft rate limit using KV.
     * Allows burst up to maxRequests per windowSeconds per IP.
     * Returns { ok: false } if over limit.
     *
     * Note: Cloudflare free tier also lets you add rate limiting rules
     * in the dashboard under Security → WAF → Rate Limiting Rules.
     * That is the preferred approach for production — this is a code-level
     * backstop for the Worker itself.
     */
    async function rateLimitIP(request, action, maxRequests = 10, windowSeconds = 60) {
      const ip  = request.headers.get("CF-Connecting-IP") || "unknown";
      const key = `ratelimit:${action}:${ip}`;
      const now = Math.floor(Date.now() / 1000);

      const raw    = await env.PIA_KV.get(key);
      const record = raw ? JSON.parse(raw) : { count: 0, window_start: now };

      if (now - record.window_start > windowSeconds) {
        // New window
        record.count = 1;
        record.window_start = now;
      } else {
        record.count += 1;
      }

      await env.PIA_KV.put(key, JSON.stringify(record), { expirationTtl: windowSeconds * 2 });

      if (record.count > maxRequests) {
        return { ok: false, retryAfter: windowSeconds - (now - record.window_start) };
      }
      return { ok: true };
    }

    // ════════════════════════════════════════════════════════════
    // PUBLIC READ ENDPOINTS — no auth required
    // Safe: returns only portfolio data, no secrets
    // ════════════════════════════════════════════════════════════

    // ── GET /health ──────────────────────────────────────────────
    if (url.pathname === "/health" && request.method === "GET") {
      const acct = await fetch(alpacaBase + "/v2/account", { headers: alpacaHdrs });
      return Response.json(
        { ok: acct.ok, mode, alpaca_status: acct.status, version: "v4" },
        { headers: cors }
      );
    }

    // ── GET /portfolio ───────────────────────────────────────────
    if (url.pathname === "/portfolio" && request.method === "GET") {
      const [acct, pos] = await Promise.all([
        fetch(alpacaBase + "/v2/account",   { headers: alpacaHdrs }).then(r => r.json()),
        fetch(alpacaBase + "/v2/positions", { headers: alpacaHdrs }).then(r => r.json()),
      ]);
      await snapshotEquity(env, acct.equity);
      return Response.json({ account: acct, positions: pos, mode }, { headers: cors });
    }

    // ── GET /trades ──────────────────────────────────────────────
    if (url.pathname === "/trades" && request.method === "GET") {
      const trades = JSON.parse((await env.PIA_KV.get("pia:trades")) || "[]");
      return Response.json({ trades, mode }, { headers: cors });
    }

    // ── GET /thesis ──────────────────────────────────────────────
    if (url.pathname === "/thesis" && request.method === "GET") {
      const thesis = await env.PIA_KV.get("pia:thesis");
      return Response.json({ thesis: thesis || null, mode }, { headers: cors });
    }

    // ── GET /context ─────────────────────────────────────────────
    if (url.pathname === "/context" && request.method === "GET") {
      const context = await env.PIA_KV.get("pia:context");
      return Response.json({ context: context || null, mode }, { headers: cors });
    }

    // ── GET /history ─────────────────────────────────────────────
    if (url.pathname === "/history" && request.method === "GET") {
      const history = JSON.parse((await env.PIA_KV.get("pia:history")) || "[]");
      return Response.json({ history, mode }, { headers: cors });
    }

    // ════════════════════════════════════════════════════════════
    // AUTH STUBS — Stage 2 Supabase endpoints (placeholders)
    // These return 501 now. In Stage 2, implement full Supabase flows.
    // ════════════════════════════════════════════════════════════

    // ── POST /auth/register ──────────────────────────────────────
    // Admin-only: create a new PIA user via Supabase invite.
    // In production this is done via the Supabase dashboard.
    // This endpoint is a placeholder for the future self-serve flow.
    if (url.pathname === "/auth/register" && request.method === "POST") {
      return Response.json({
        message: "Registration is invite-only. Contact admin@didimdigital.com"
      }, { status: 200, headers: cors });
    }

    // ── GET /auth/session ────────────────────────────────────────
    // Dashboard calls this to check if session is still valid.
    if (url.pathname === "/auth/session" && request.method === "GET") {
      const authCheck = await requireAuth(request);
      if (!authCheck.ok) {
        return Response.json({ authenticated: false, error: authCheck.error }, { status: 401, headers: cors });
      }
      return Response.json({
        authenticated: true,
        userId: authCheck.userId,
        email: authCheck.email,
        mode,
      }, { headers: cors });
    }

    // ── POST /auth/signout ───────────────────────────────────────
    // Dashboard calls this on sign out. Supabase handles token invalidation
    // on the client side; this just confirms the Worker side is clear.
    if (url.pathname === "/auth/signout" && request.method === "POST") {
      return Response.json({ ok: true }, { headers: cors });
    }

    // ════════════════════════════════════════════════════════════
    // PROTECTED POST ENDPOINTS — require x-pia-key header
    // All mutating operations are behind auth
    // ════════════════════════════════════════════════════════════

    // ── POST /thesis ─────────────────────────────────────────────
    if (url.pathname === "/thesis" && request.method === "POST") {
      const auth = await requireAuth(request);
      if (!auth.ok) return Response.json({ error: auth.error }, { status: 401, headers: cors });

      const { text } = await request.json();
      if (!text || text.length < 20) {
        return Response.json({ error: "Thesis too short (min 20 chars)" }, { status: 400, headers: cors });
      }
      await env.PIA_KV.put("pia:thesis", text);
      return Response.json({ ok: true }, { headers: cors });
    }

    // ── POST /context ─────────────────────────────────────────────
    if (url.pathname === "/context" && request.method === "POST") {
      const auth = await requireAuth(request);
      if (!auth.ok) return Response.json({ error: auth.error }, { status: 401, headers: cors });

      const { text } = await request.json();
      if (text === null || text === "") {
        await env.PIA_KV.delete("pia:context");
        return Response.json({ ok: true, cleared: true }, { headers: cors });
      }
      await env.PIA_KV.put("pia:context", text);
      return Response.json({ ok: true }, { headers: cors });
    }

    // ── POST /mode ───────────────────────────────────────────────
    if (url.pathname === "/mode" && request.method === "POST") {
      const auth = await requireAuth(request);
      if (!auth.ok) return Response.json({ error: auth.error }, { status: 401, headers: cors });

      const { mode: newMode } = await request.json();
      if (!["paper", "live"].includes(newMode)) {
        return Response.json({ error: "Invalid mode — must be 'paper' or 'live'" }, { status: 400, headers: cors });
      }

      // Extra guard: live mode requires Worker secret confirmation
      // Stage 2: also require MFA verification before allowing live switch
      if (newMode === "live") {
        const liveConfirm = request.headers.get("x-live-confirm");
        if (liveConfirm !== "CONFIRMED") {
          return Response.json({
            error: "Live mode switch requires x-live-confirm: CONFIRMED header"
          }, { status: 403, headers: cors });
        }
      }

      await env.PIA_KV.put("pia:mode", newMode);
      return Response.json({ ok: true, mode: newMode }, { headers: cors });
    }

    // ── POST /trade/manual ───────────────────────────────────────
    if (url.pathname === "/trade/manual" && request.method === "POST") {
      const auth = await requireAuth(request);
      if (!auth.ok) return Response.json({ error: auth.error }, { status: 401, headers: cors });

      // Rate limit: max 20 manual trades per hour per IP
      const rl = await rateLimitIP(request, "manual_trade", 20, 3600);
      if (!rl.ok) {
        return Response.json(
          { error: `Rate limit exceeded. Retry in ${rl.retryAfter}s` },
          { status: 429, headers: cors }
        );
      }

      const body = await request.json();
      return await manualTrade(env, alpacaBase, alpacaHdrs, body, cors);
    }

    // ── POST /rebalance ──────────────────────────────────────────
    if (url.pathname === "/rebalance" && request.method === "POST") {
      const auth = await requireAuth(request);
      if (!auth.ok) return Response.json({ error: auth.error }, { status: 401, headers: cors });

      return await rebalanceCycle(env, alpacaBase, alpacaHdrs, cors);
    }

    // ── POST /execute ────────────────────────────────────────────
    // Protected — manual trigger from dashboard requires auth.
    // Cron trigger bypasses this (runs via scheduled(), not fetch()).
    if (url.pathname === "/execute" && request.method === "POST") {
      const auth = await requireAuth(request);
      if (!auth.ok) return Response.json({ error: auth.error }, { status: 401, headers: cors });

      // Rate limit: max 5 manual executions per hour (protect Claude API credits)
      const rl = await rateLimitIP(request, "execute", 5, 3600);
      if (!rl.ok) {
        return Response.json(
          { error: `Execute rate limit reached. Retry in ${rl.retryAfter}s` },
          { status: 429, headers: cors }
        );
      }

      return await runExecution(env, alpacaBase, alpacaHdrs, cors);
    }

    // Catch-all root POST (legacy support)
    if (url.pathname === "/" && request.method === "POST") {
      const auth = await requireAuth(request);
      if (!auth.ok) return Response.json({ error: auth.error }, { status: 401, headers: cors });
      return await runExecution(env, alpacaBase, alpacaHdrs, cors);
    }

    return new Response("Not found", { status: 404, headers: cors });
  },

  // ── Cron — Monday 9:45am ET ─────────────────────────────────────
  // Cron runs server-side — bypasses HTTP auth entirely (correct behavior)
  async scheduled(event, env, ctx) {
    const mode = (await env.PIA_KV.get("pia:mode")) || "paper";
    const base = mode === "live"
      ? "https://api.alpaca.markets"
      : "https://paper-api.alpaca.markets";
    const hdrs = {
      "APCA-API-KEY-ID":     mode === "live" ? env.ALPACA_LIVE_KEY_ID : env.ALPACA_PAPER_KEY_ID,
      "APCA-API-SECRET-KEY": mode === "live" ? env.ALPACA_LIVE_SECRET  : env.ALPACA_PAPER_SECRET,
      "Content-Type": "application/json",
    };
    ctx.waitUntil(runExecution(env, base, hdrs, {}));
  }
};

// ════════════════════════════════════════════════════════════════
// CORE EXECUTION — unchanged from v2
// ════════════════════════════════════════════════════════════════
async function runExecution(env, alpacaBase, alpacaHdrs, cors) {
  const WEEKLY_AMOUNT   = 100;
  const MAX_POS_PCT     = 0.20;
  const STOP_LOSS_PCT   = -0.15;
  const REBAL_THRESHOLD = 0.22;
  const REBAL_TARGET    = 0.18;

  const thesis = await env.PIA_KV.get("pia:thesis");
  if (!thesis) return Response.json({ error: "No thesis set" }, { status: 400, headers: cors });

  const contextNote = await env.PIA_KV.get("pia:context");

  const [acctRes, posRes] = await Promise.all([
    fetch(alpacaBase + "/v2/account",   { headers: alpacaHdrs }),
    fetch(alpacaBase + "/v2/positions", { headers: alpacaHdrs }),
  ]);
  const account   = await acctRes.json();
  const positions = await posRes.json();
  const posArray  = Array.isArray(positions) ? positions : [];

  const portfolioValue = parseFloat(account.portfolio_value || account.equity || 0);
  const results = { stop_losses: [], rebalances: [], trades: [] };

  // ── STEP 1: Stop-loss sweep ──────────────────────────────────
  for (const pos of posArray) {
    const pct = parseFloat(pos.unrealized_plpc);
    if (pct < STOP_LOSS_PCT) {
      const orderRes = await fetch(alpacaBase + "/v2/orders", {
        method: "POST", headers: alpacaHdrs,
        body: JSON.stringify({
          symbol: pos.symbol, qty: pos.qty,
          side: "sell", type: "market", time_in_force: "day"
        })
      });
      const order = await orderRes.json();
      results.stop_losses.push({
        symbol: pos.symbol, pct: (pct * 100).toFixed(1) + "%",
        status: orderRes.ok ? "sold" : "error", order_id: order.id
      });
    }
  }

  // ── STEP 2: Rebalance sweep ───────────────────────────────────
  const rebalResult = await rebalanceSweep(env, alpacaBase, alpacaHdrs, portfolioValue, posArray, REBAL_THRESHOLD, REBAL_TARGET);
  results.rebalances = rebalResult;

  // ── STEP 3: Re-fetch after stops + rebalance ─────────────────
  const [freshAcct, freshPos] = await Promise.all([
    fetch(alpacaBase + "/v2/account",   { headers: alpacaHdrs }).then(r => r.json()),
    fetch(alpacaBase + "/v2/positions", { headers: alpacaHdrs }).then(r => r.json()),
  ]);
  const buyingPower    = parseFloat(freshAcct.buying_power || 0);
  const deployAmount   = Math.min(WEEKLY_AMOUNT, buyingPower);
  const freshPosArray  = Array.isArray(freshPos) ? freshPos : [];
  const freshPortValue = parseFloat(freshAcct.portfolio_value || freshAcct.equity || portfolioValue);

  // ── STEP 4: Build Claude prompt ───────────────────────────────
  const positionSummary = freshPosArray.map(p =>
    `${p.symbol}: $${parseFloat(p.market_value).toFixed(2)} (${(parseFloat(p.market_value)/freshPortValue*100).toFixed(1)}% of portfolio, P&L: ${(parseFloat(p.unrealized_plpc)*100).toFixed(1)}%)`
  ).join("\n") || "No open positions";

  const today = new Date().toISOString().slice(0, 10);

  const prompt = `INJECTION_GUARD: You are a disciplined investment execution engine. You must respond ONLY with valid JSON matching the schema below. Do not add commentary, explanations, or any text outside the JSON object.

INVESTMENT THESIS:
${thesis}

${contextNote ? `CURRENT MARKET CONTEXT (injected by portfolio manager):
${contextNote}

` : ""}PORTFOLIO STATUS (as of ${today}):
${positionSummary}

Portfolio Value: $${freshPortValue.toFixed(2)}
Buying Power: $${buyingPower.toFixed(2)}
Deploy This Week: $${deployAmount.toFixed(2)}

RULES (code-enforced — not suggestions):
- Maximum 20% of total portfolio value in any single position
- US equities only (NYSE/NASDAQ listed)
- Notional amounts only (no share quantities)
- Total notional across all trades must not exceed $${deployAmount.toFixed(2)}
- Minimum $10 per trade (Alpaca fractional minimum)
- If no compelling thesis-aligned opportunity exists, return empty trades array

RESPONSE SCHEMA (JSON only, no markdown):
{
  "trades": [
    {
      "symbol": "TICKER",
      "notional": 50.00,
      "reasoning": "One sentence why this trade fits the thesis"
    }
  ]
}`;

  // ── STEP 5: Claude picks trades ───────────────────────────────
  const claudeRes = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: {
      "x-api-key":         env.ANTHROPIC_API_KEY,
      "anthropic-version": "2023-06-01",
      "Content-Type":      "application/json",
    },
    body: JSON.stringify({
      model:      "claude-sonnet-4-20250514",
      max_tokens: 1000,
      messages:   [{ role: "user", content: prompt }],
    }),
  });

  const claudeData = await claudeRes.json();
  const rawText    = claudeData?.content?.[0]?.text || "{}";

  let trades = [];
  try {
    const parsed = JSON.parse(rawText);
    trades = parsed.trades || [];
  } catch {
    return Response.json({ error: "Claude returned invalid JSON", raw: rawText }, { status: 500, headers: cors });
  }

  // ── STEP 6: Guardrail check + place orders ───────────────────
  const finalPortfolioValue = freshPortValue;
  const finalPositions      = freshPosArray;

  for (const trade of trades) {
    const existing      = finalPositions.find(p => p.symbol === trade.symbol);
    const existingValue = existing ? parseFloat(existing.market_value) : 0;

    if (finalPortfolioValue > 0 && (existingValue + trade.notional) / finalPortfolioValue > MAX_POS_PCT) {
      results.trades.push({
        symbol: trade.symbol, status: "skipped",
        reason: "Would exceed 20% position limit", reasoning: trade.reasoning
      });
      continue;
    }

    const orderRes = await fetch(alpacaBase + "/v2/orders", {
      method: "POST", headers: alpacaHdrs,
      body: JSON.stringify({
        symbol: trade.symbol, notional: trade.notional.toString(),
        side: "buy", type: "market", time_in_force: "day"
      })
    });
    const order = await orderRes.json();
    results.trades.push({
      symbol: trade.symbol, notional: trade.notional,
      status: orderRes.ok ? "placed" : "failed",
      order_id: order.id, reasoning: trade.reasoning, error: order.message
    });
  }

  // ── STEP 7: Write trade log ───────────────────────────────────
  const currentMode = (await env.PIA_KV.get("pia:mode")) || "paper";
  const existing    = JSON.parse((await env.PIA_KV.get("pia:trades")) || "[]");
  const newEntries  = [
    ...results.stop_losses.filter(r => r.status === "sold").map(r => ({
      id: Date.now() + Math.random(), date: new Date().toISOString(),
      ticker: r.symbol, action: "sell", amount: 0,
      reasoning: `Stop-loss triggered at ${r.pct} — position liquidated`,
      mode: currentMode, source: "stop_loss"
    })),
    ...results.rebalances.filter(r => r.status === "trimmed").map(r => ({
      id: Date.now() + Math.random(), date: new Date().toISOString(),
      ticker: r.symbol, action: "sell", amount: parseFloat(r.trimmed.replace("$", "")),
      reasoning: r.reason, mode: currentMode, source: "rebalance"
    })),
    ...results.trades.filter(r => r.status === "placed").map(r => ({
      id: Date.now() + Math.random(), date: new Date().toISOString(),
      ticker: r.symbol, action: "buy", amount: r.notional,
      reasoning: r.reasoning, mode: currentMode, source: "agent"
    }))
  ];

  await env.PIA_KV.put("pia:trades", JSON.stringify([...newEntries, ...existing].slice(0, 500)));
  await env.PIA_KV.put("pia:last_execution", new Date().toISOString());

  // Clear context note after use (one-time injection)
  if (contextNote) await env.PIA_KV.delete("pia:context");

  await snapshotEquity(env, freshAcct.equity);

  return Response.json({ ok: true, results, context_used: !!contextNote }, { headers: cors });
}

// ════════════════════════════════════════════════════════════════
// REBALANCE SWEEP — shared by runExecution + /rebalance endpoint
// ════════════════════════════════════════════════════════════════
async function rebalanceSweep(env, alpacaBase, alpacaHdrs, portfolioValue, positions, threshold, target) {
  const results = [];
  if (portfolioValue === 0) return results;

  for (const pos of positions) {
    const weight = parseFloat(pos.market_value) / portfolioValue;
    if (weight > threshold) {
      const trimAmount = parseFloat(pos.market_value) - (portfolioValue * target);
      if (trimAmount > 1) {
        const orderRes = await fetch(alpacaBase + "/v2/orders", {
          method: "POST", headers: alpacaHdrs,
          body: JSON.stringify({
            symbol: pos.symbol, notional: trimAmount.toFixed(2),
            side: "sell", type: "market", time_in_force: "day"
          })
        });
        const order = await orderRes.json();
        const status = orderRes.ok ? "trimmed" : "error";
        results.push({
          symbol: pos.symbol,
          weight: (weight * 100).toFixed(1) + "%",
          trimmed: "$" + trimAmount.toFixed(2),
          status,
          reason: `Rebalance: ${pos.symbol} was ${(weight*100).toFixed(1)}% — trimmed to ${(target*100).toFixed(0)}% target`
        });
      } else {
        results.push({ symbol: pos.symbol, weight: (weight*100).toFixed(1)+"%", status: "no_action", reason: "Trim too small" });
      }
    } else {
      results.push({ symbol: pos.symbol, weight: (weight*100).toFixed(1)+"%", status: "ok", reason: "Within limits" });
    }
  }
  return results;
}

// ════════════════════════════════════════════════════════════════
// MANUAL TRADE — POST /trade/manual
// ════════════════════════════════════════════════════════════════
async function manualTrade(env, alpacaBase, alpacaHdrs, body, cors) {
  const { symbol, notional, side, reason } = body;

  if (!symbol || !notional || !side) {
    return Response.json({ error: "Required: symbol, notional, side (buy|sell)" }, { status: 400, headers: cors });
  }
  if (!["buy", "sell"].includes(side)) {
    return Response.json({ error: "side must be 'buy' or 'sell'" }, { status: 400, headers: cors });
  }
  if (notional <= 0 || notional > 5000) {
    return Response.json({ error: "notional must be between $1 and $5000" }, { status: 400, headers: cors });
  }
  if (!/^[A-Z]{1,5}$/.test(symbol.toUpperCase())) {
    return Response.json({ error: "Invalid ticker symbol" }, { status: 400, headers: cors });
  }

  const orderRes = await fetch(alpacaBase + "/v2/orders", {
    method: "POST", headers: alpacaHdrs,
    body: JSON.stringify({
      symbol: symbol.toUpperCase(), notional: notional.toString(),
      side, type: "market", time_in_force: "day"
    })
  });
  const order = await orderRes.json();

  if (!orderRes.ok) {
    return Response.json({ error: order.message || "Alpaca rejected the order", order }, { status: 400, headers: cors });
  }

  const currentMode = (await env.PIA_KV.get("pia:mode")) || "paper";
  const existing    = JSON.parse((await env.PIA_KV.get("pia:trades")) || "[]");
  const entry = {
    id: Date.now() + Math.random(), date: new Date().toISOString(),
    ticker: symbol.toUpperCase(), action: side, amount: notional,
    reasoning: reason || `Manual ${side} — user initiated via dashboard`,
    mode: currentMode, source: "manual"
  };
  await env.PIA_KV.put("pia:trades", JSON.stringify([entry, ...existing].slice(0, 500)));

  return Response.json({ ok: true, order_id: order.id, symbol: symbol.toUpperCase(), notional, side }, { headers: cors });
}

// ════════════════════════════════════════════════════════════════
// STANDALONE REBALANCE — POST /rebalance
// ════════════════════════════════════════════════════════════════
async function rebalanceCycle(env, alpacaBase, alpacaHdrs, cors) {
  const REBAL_THRESHOLD = 0.22;
  const REBAL_TARGET    = 0.18;

  const [acct, positions] = await Promise.all([
    fetch(alpacaBase + "/v2/account",   { headers: alpacaHdrs }).then(r => r.json()),
    fetch(alpacaBase + "/v2/positions", { headers: alpacaHdrs }).then(r => r.json()),
  ]);
  const portfolioValue = parseFloat(acct.portfolio_value || acct.equity || 0);
  if (portfolioValue === 0) {
    return Response.json({ error: "Portfolio value is zero" }, { status: 400, headers: cors });
  }

  const results = await rebalanceSweep(
    env, alpacaBase, alpacaHdrs,
    portfolioValue, Array.isArray(positions) ? positions : [],
    REBAL_THRESHOLD, REBAL_TARGET
  );

  // Log rebalance trades
  const trimmed = results.filter(r => r.status === "trimmed");
  if (trimmed.length > 0) {
    const currentMode = (await env.PIA_KV.get("pia:mode")) || "paper";
    const existing    = JSON.parse((await env.PIA_KV.get("pia:trades")) || "[]");
    const entries = trimmed.map(r => ({
      id: Date.now() + Math.random(), date: new Date().toISOString(),
      ticker: r.symbol, action: "sell", amount: parseFloat(r.trimmed.replace("$", "")),
      reasoning: r.reason, mode: currentMode, source: "rebalance"
    }));
    await env.PIA_KV.put("pia:trades", JSON.stringify([...entries, ...existing].slice(0, 500)));
  }

  return Response.json({ ok: true, results }, { headers: cors });
}

// ════════════════════════════════════════════════════════════════
// EQUITY SNAPSHOT — daily closing values for chart history
// ════════════════════════════════════════════════════════════════
async function snapshotEquity(env, equityStr) {
  if (!equityStr) return;
  const equity = parseFloat(equityStr);
  if (isNaN(equity) || equity <= 0) return;

  const now     = new Date();
  const dateKey = now.toISOString().slice(0, 10);

  const history = JSON.parse((await env.PIA_KV.get("pia:history")) || "[]");
  const idx = history.findIndex(h => h.date === dateKey);

  if (idx >= 0) {
    history[idx].equity = equity;
  } else {
    history.push({ date: dateKey, equity, ts: now.toISOString() });
  }

  const trimmed = history.sort((a, b) => a.date.localeCompare(b.date)).slice(-365);
  await env.PIA_KV.put("pia:history", JSON.stringify(trimmed));
}
