# AMNIX Frontend

Introduced in Step 12A. React 19 + TypeScript + Vite, styled with Tailwind CSS v4 (CSS-first `@theme` tokens — see `frontend/src/styles/tokens.css`).

## Running locally

```
cd frontend
npm install
npm run dev       # http://localhost:5173
```

Requires the backend running separately (see `backend/README`/docs) and reachable at the URL configured in `frontend/.env.local` (copy from `frontend/.env.example`):

```
VITE_API_BASE_URL=http://localhost:8000
```

The backend's `CORS_ALLOWED_ORIGINS` must include the frontend's origin (`http://localhost:5173` by default) — see `backend/.env.example`'s own comment for the exact line to uncomment.

Other scripts: `npm run build`, `npm run test` (Vitest + Testing Library), `npm run lint` (oxlint).

## Design system

Dark enterprise SOC aesthetic, sharing design DNA with KANZ (layered dark surfaces, thin technical borders, restrained cyan/blue accent, high-hierarchy typography) without copying it — the KANZ repository was not present in this workspace when this was built (see Step 12A's final report for the full discovery note), so AMNIX's tokens are original values chosen to be compatible with that direction, not derived from it.

All color/spacing/radius/motion values are tokens defined once in `frontend/src/styles/tokens.css` (`@theme` block) and consumed via Tailwind utility classes (`bg-surface`, `text-fg-muted`, `border-border-strong`, ...) — no component hardcodes a raw hex value. Severity (`critical`/`high`/`medium`/`low`) and status (`success`/`warning`/`danger`) each have their own token pair (a saturated color + a dim background), used consistently everywhere severity/status appears (badges, chart series, severity distribution).

## Motion philosophy

Motion communicates feedback, hierarchy, state, or discovery — never decoration alone. `motion/react` powers: the sidebar's active-item indicator (a `layoutId`-animated pill/rail), metric-card entrance and count-up, the recent-alerts list's staggered entrance, chart draw-in (Recharts' own animation), and the command palette's/user menu's fade+scale transitions. Every animated value respects `prefers-reduced-motion` — either through a global CSS override (`tokens.css`) that collapses all transition/animation durations to near-zero, or, where a value is computed imperatively (the metric count-up), by checking `matchMedia('(prefers-reduced-motion: reduce)')` directly and skipping straight to the final value.

## Routes

| Path | Page | Auth |
|---|---|---|
| `/login` | Sign in | Public (redirects to `/dashboard` if already authenticated) |
| `/dashboard` | SOC overview — metrics, threat activity, recent alerts, severity distribution, MITRE activity, system status | Protected |
| `/alerts`, `/events`, `/investigations`, `/copilot`, `/audits` | Placeholder screens for future milestones | Protected |
| `/settings` | Placeholder | Protected |

Unauthenticated access to a protected route redirects to `/login`; a successful login returns to the originally requested route (or `/dashboard`).

## API integration

`frontend/src/services/*Service.ts` provide typed clients for every endpoint listed in Step 12A's brief (auth login/refresh, events, alerts + status + investigation, Copilot ask/follow-up/audits, admin audits + user status). `frontend/src/types/api.ts` mirrors the backend's real Pydantic schemas field-for-field.

**Token storage is in-memory only** (`frontend/src/services/tokenStore.ts`) — not localStorage, not sessionStorage, not cookies. This was a deliberate decision based on the actual backend contract: AMNIX authenticates exclusively via an `Authorization: Bearer` header (no cookie support exists), and `CORSMiddleware` runs with `allow_credentials=False`, so a cookie-based approach isn't available even in principle. The refresh token is long-lived (7 days) and persisting it in Web Storage would leave it readable by any successful XSS for its entire lifetime. The real cost of this choice: a full page reload loses the session and requires signing in again — see the Step 12A final report's Known Limitations for the full trade-off discussion.

The dashboard's alert list/metrics/activity chart currently render isolated, clearly-labeled frontend demo data (`frontend/src/features/dashboard/demoData.ts`) — the backend has no list/aggregate endpoint for alerts or events yet, only single-resource lookups. `frontend/src/features/dashboard/dashboardService.ts` is the one function to change once such an endpoint exists.
