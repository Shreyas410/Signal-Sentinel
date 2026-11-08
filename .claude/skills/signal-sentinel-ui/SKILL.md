---
name: signal-sentinel-ui
description: Use for any UI work on Signal Sentinel (templates/, static/). Enforces the project's dark analyst-console design direction and bans generic AI-generated UI patterns.
---

# Signal Sentinel UI direction

## What this is
An analyst console for security work. Users scan threat feeds, review drafted
detection rules, and approve or reject them. Priorities: scannability, trust,
speed. It is NOT a marketing site.

## Aesthetic
Calm, dense, instrument-panel, dark base. Think terminal + editorial table,
not "cyber".
- Near-black surfaces stepped by elevation (bg, surface-1/2/3), separated by
  1px borders. No drop shadows on cards, no glow.
- ONE accent color, used only for interactive elements and focus.
- Severity is the only other color: critical / high / medium / low, defined
  once as CSS variables, always paired with a text label (never color alone).
- Monospace for data: CVE IDs, domains, rule patterns, hashes, timestamps,
  metric numerals. A distinctive sans for headings and UI text.
- Radius 2-4px max. Nothing pill-shaped except status tags.

## Tokens
- All colors, type, spacing, radius, borders live as CSS variables in
  static/tokens.css. Use ONLY these.
- Never hardcode a hex, px spacing, or font stack outside tokens.css.
- If a needed value is missing, add it to tokens.css and mention it.

## Layout rules
- /app: persistent left rail (collapses to a top bar on narrow screens) for the
  4 sections. No hero banners inside the app.
- Prefer dense tables and lists over card grids.
- Rule approval is the core workflow: show the drafted rule, its source feed
  entry, what it would match, and Approve/Reject together on one screen. Make
  the human-in-the-loop step obvious and hard to click by accident.
- Metrics: precision/recall/F1 as large plain numerals with labels, plus one
  simple table or chart. No decorative gauges.
- Landing page (/): one clear sentence on what it does, the two enforcement
  layers explained concretely, a link to /app. No gradient hero, no
  three-identical-cards row.

## Banned
Purple/blue gradients, neon green-on-black, glassmorphism, glowing borders,
emoji or shield/lock clip-art as icons, centered hero + two buttons, three
equal feature cards, fake testimonials or invented stats, filler words
(seamless, powerful, revolutionize, elevate, unlock, next-gen).

## Content
Use real data from data/ and the live feeds. Test with long domains, empty
feeds, offline-cache fallback, and error states. Show the offline fallback
state explicitly in the UI.

## States and accessibility
Every interactive element needs hover, focus-visible, disabled, and loading
states. Empty and error states get real copy, not blank space. Contrast at
least 4.5:1. Keyboard-navigable approval flow. Respect prefers-reduced-motion.

## Process
1. Before coding, state the layout and token choices in 5 lines.
2. Plain CSS with variables. No new framework or UI library.
3. Run the app, screenshot / and /app at desktop and ~390px width.
4. Critique the screenshots against this file, list what looks generic, fix it.
5. Make targeted edits; don't rewrite pages that already follow the direction.
