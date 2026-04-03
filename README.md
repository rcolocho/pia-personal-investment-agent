# PIA — Personal Investment Agent
> Live AI trading agent that executes a user-authored investment thesis every Monday morning via the Alpaca brokerage API, powered by Anthropic Claude. Not a demo. Runs on real infrastructure with real money.

**Live:** [didimdigital.com/pia](https://didimdigital.com/pia) · **Dashboard:** [didimdigital.com/pia-dashboard](https://didimdigital.com/pia-dashboard) · **Built by:** Robin Colocho · **Status:** Live (Paper Trading)

---

## What it does

PIA executes a user-written investment thesis every Monday at 9:45am ET — automatically, with no manual intervention. The user writes their conviction in plain English ("I believe AI infrastructure spending will grow for the next 18 months") and PIA executes that thesis with discipline: buying positions, enforcing allocation limits, trimming overweight holdings, and liquidating stop-loss breaches.

No emotion. No panic selling. No FOMO buying.

## Tech stack

| Layer | Technology | Role |
|-------|-----------|------|
| AI Engine | Anthropic Claude API (claude-sonnet) | Reads thesis + live portfolio → returns JSON trade decisions with reasoning |
| Brokerage | Alpaca Markets REST API | Executes real equity orders, returns live portfolio and position data |
| Serverless API | Cloudflare Worker (pia-agent.alex-b7b.workers.dev) | All server-side logic: AI execution, trading, KV state, guardrails |
| Persistent State | Cloudflare KV (pia-state namespace) | Stores thesis, mode, trade history, execution context across sessions |
| Scheduler | Cloudflare Cron Trigger | Fires execution cycle every Monday at 9:45am ET automatically |
| Dashboard UI | HTML/CSS/JS + Chart.js | Passphrase-gated control panel — stats, equity chart vs SPY, thesis editor, trade log |
| Hosting | Hostinger + Cloudflare CDN | Static pages, DDoS protection, SSL |

## Key features

- **Autonomous execution** — Cron trigger fires every Monday. Zero manual steps.
- **Thesis-driven AI** — Claude reads investment conviction + live portfolio, selects trades, returns structured JSON with reasoning
- **Guardrails** — Max position size, stop-loss enforcement, allocation caps enforced before every execution
- **Performance tracking** — Equity line vs SPY overlay, 7D/30D/90D/All time tabs, Chart.js visualization
- **KV persistence** — State survives Worker restarts. Thesis, mode, full trade history always available
- **Cost:** ~$0.02/execution · Cloudflare Worker free tier · Alpaca zero-commission · Total: under $1/month

## The cost proof point

> An enterprise equivalent — managed trading infrastructure, LLM integration, compliance logging, dedicated servers — would cost **$200,000–$2,000,000 to build** and **$20,000–$100,000/month to operate**. PIA runs the same core architecture for under $1/month.

## Product decisions & what I learned

- Chose Cloudflare Workers over AWS Lambda because KV storage, cron triggers, and API proxying are all in one free-tier platform — zero additional accounts
- Thesis in plain English (not structured JSON) was a deliberate PM decision — lowers the barrier to use and lets Claude interpret nuance rather than forcing rigid parameters
- Paper trading first was the right call — caught edge cases in position sizing logic before real money was at risk
- The same architecture applies directly to consumer banking AI at companies like Axos, SoFi, and Robinhood — an agentic layer that acts on the customer's behalf rather than just displaying their balance

## Demo

Watch the build walkthrough on YouTube: [youtube.com/@RobinColocho](https://www.youtube.com/@RobinColocho)

---
*Built by Robin Alexander Colocho · [Didim Digital](https://didimdigital.com) · [LinkedIn](https://linkedin.com/in/rcolocho)*
