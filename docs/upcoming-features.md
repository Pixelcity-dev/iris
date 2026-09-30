# Upcoming Features — Iris Roadmap

> **Status: Announcement.** The features below are documented today so you can
> plan; they ship over the next few Iris updates. No runtime behavior is
> enabled yet. Track progress in the changelog of upcoming releases.

## AI Agent — AI-assisted remediation <span style="badge">UPCOMING</span>

The Iris AI Agent helps you understand and fix findings directly from the
CLI and the dashboard.

**What it will do**

- `iris ai explain <finding>` — plain-language explanation of a finding,
  grounded in the rule, the code snippet and the compliance mapping
- `iris ai fix <finding>` — generates a concrete patch suggestion for the
  flagged location (as a diff you review, never auto-applied)
- `iris ai review` — post-scan debrief: prioritized fix plan with effort
  estimates
- Dashboard: chat-style follow-up questions on any scan result

**Fair-use and limits (by design)**

- **Active usage limits**: AI requests are metered per account and plan
  (pages of context per day/month). Limits are enforced server-side and shown
  live in `iris cloud status` and the dashboard ("AI pages" meter).
- **No model training — ever**: your source code, findings, snippets and
  prompts are **never used to train or fine-tune models**. Zero-retention
  processing; requests are not stored after the response is returned.
- Data residency: processing happens in the EU (PixelCity infrastructure).
- Opt-in per account; the agent never runs automatically.

**Availability**: Pro and Enterprise plans at launch; free tier gets a small
monthly trial quota. Docs: `iris ai --help` once enabled.

## Also on the roadmap

| Feature | What it does | Status |
|---|---|---|
| Team & Organizations | Shared baselines, org-wide policies, per-team usage | Planned |
| Scheduled Cloud Scans | Cron-style recurring scans with drift alerts | Planned |
| IDE Extensions | VS Code / JetBrains: findings inline, fix via AI Agent | Planned |
| Iris Cloud API | Programmatic scans + webhook results for your pipeline | Planned |

---

*Questions or early-access interest: service@pixelcity.dev*
