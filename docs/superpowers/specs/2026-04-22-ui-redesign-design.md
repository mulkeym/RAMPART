# RAMPART UI Redesign: Command Center Dark

## Overview

Comprehensive visual redesign of the RAMPART admin UI from its current light/teal theme to a dark "Command Center" aesthetic. The redesign is an in-place upgrade within `ui.py` — no new files, no build tools, no frontend framework. Minimal inline JavaScript is added for confirmation dialogs and inline form validation.

## Goals

1. **Visual identity** — Dark, security-operations-center aesthetic with cyan accents that reinforces RAMPART's role as a security policy gateway
2. **Better UX** — Confirmation dialogs for destructive actions, inline form validation, dashboard stats cards, enhanced table presentation
3. **Polish** — Hover transitions, color-coded severity/status badges, consistent spacing and typography

## Constraints

- All changes stay within `ui.py` (in-place upgrade)
- No npm, no build tools, no CDN dependencies
- JavaScript limited to small inline `<script>` blocks (confirms, validation)
- System font stack only (no web font loading)
- Must remain fully functional with zero-JS (dialogs fall back to native `confirm()`)

## Color System

### CSS Custom Properties

```css
:root {
  color-scheme: dark;
  --bg: #0b0f14;
  --bg-header: #111820;
  --panel: #151d27;
  --panel-hover: #1c2737;
  --text: #e2e8f0;
  --text-secondary: #94a3b8;
  --muted: #64748b;
  --border: rgba(255, 255, 255, 0.08);
  --border-strong: rgba(255, 255, 255, 0.12);
  --primary: #38bdf8;
  --primary-hover: #22d3ee;
  --primary-text: #0b0f14;
  --success: #4ade80;
  --success-bg: rgba(74, 222, 128, 0.08);
  --success-border: rgba(74, 222, 128, 0.2);
  --danger: #f87171;
  --danger-bg: rgba(248, 113, 113, 0.08);
  --danger-border: rgba(248, 113, 113, 0.2);
  --warning: #fbbf24;
  --warning-bg: rgba(251, 191, 36, 0.08);
  --warning-border: rgba(251, 191, 36, 0.2);
}
```

### Layered Backgrounds

| Layer | Color | Usage |
|-------|-------|-------|
| Body | `#0b0f14` | Page background |
| Header | `#111820` | Top navigation bar |
| Panel | `#151d27` | Cards, tables, forms |
| Hover/TH | `#1c2737` | Table headers, row hover |

## Typography

- **Font stack:** `-apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif` (unchanged, no CDN)
- **Monospace:** `"SFMono-Regular", Consolas, monospace`
- **Base size:** 14px (down from 15px) with 1.5 line-height
- **Page title:** 26px / 700 weight
- **Labels:** 13px / 600 weight, `--text-secondary` color
- **Table headers:** 11px / uppercase / `--muted` color

## Component Designs

### Header

- Background: `--bg-header` with a 1px bottom border in `rgba(56, 189, 248, 0.15)` (subtle cyan glow)
- Brand name "RAMPART" in `--primary` (cyan), letter-spacing 1.5px
- Subtitle in `rgba(255, 255, 255, 0.4)`
- Active nav link: cyan text with 2px bottom border
- Inactive nav links: `rgba(255, 255, 255, 0.55)`
- Log Out button: transparent with subtle white border

### Stats Cards (New)

Added to the Policies index page between the toolbar and the table. Four cards in a responsive grid:

| Card | Value Source | Color |
|------|-------------|-------|
| Total Policies | `len(config.policies)` | Default text, green sub-count for enabled |
| API Keys | `len(list_clients(...))` | Default text, green sub-count for active |
| Violations (24h) | `len(events)` filtered to 24h | Red if > 0 |
| Failed Requests | Distinct failed requests from events | Amber |

The `policies_index` route will need to additionally load clients (`list_clients`) and events (`load_evaluation_events`) to populate these cards. This is acceptable since these are lightweight reads.

Each card:
- Background: `--panel`
- Border: `--border`
- Border-radius: 8px
- Label: 11px uppercase muted
- Value: 28px / 700 weight
- Sub-text: 12px in semantic color

Violations page gets similar cards: total violations, high/critical count, unique customers, unique policies.

### Tables

- Panel background: `--panel`
- Header row: `--panel-hover` background
- Alternating rows: every other row gets `rgba(255, 255, 255, 0.02)` tint
- Row hover: `rgba(255, 255, 255, 0.04)` background transition
- Row borders: `rgba(255, 255, 255, 0.04)`
- Code/ID cells: cyan-colored monospace

### Severity Badges

Color-coded pill badges based on severity:

| Severity | Text | Background |
|----------|------|------------|
| critical | `#f87171` | `rgba(248, 113, 113, 0.12)` |
| high | `#fbbf24` | `rgba(251, 191, 36, 0.12)` |
| medium | `#94a3b8` | `rgba(148, 163, 184, 0.1)` |
| low | `#64748b` | `rgba(100, 116, 139, 0.1)` |

### Status Badges

| Status | Text | Background |
|--------|------|------------|
| enabled | `#4ade80` | `rgba(74, 222, 128, 0.12)` |
| disabled | `#64748b` | `rgba(100, 116, 139, 0.15)` |

### Buttons

| Variant | Background | Text | Border |
|---------|-----------|------|--------|
| Primary | `--primary` (solid) | `--primary-text` (dark) | none |
| Secondary | `rgba(255,255,255,0.06)` | `--text-secondary` | `rgba(255,255,255,0.1)` |
| Danger (small) | `--danger-bg` | `--danger` | `--danger-border` |
| Enable (small) | `--success-bg` | `--success` | `--success-border` |

All buttons: `transition: filter 0.15s` with `filter: brightness(1.15)` on hover.

### Form Inputs

- Background: `--bg` (deepest dark)
- Border: `--border`
- Text: `--text`
- Focus state: border changes to `rgba(56, 189, 248, 0.5)`, box-shadow `0 0 0 3px rgba(56, 189, 248, 0.08)`
- Invalid state: border changes to `rgba(248, 113, 113, 0.5)`, box-shadow `0 0 0 3px rgba(248, 113, 113, 0.08)`
- Error message: 12px `--danger` text below the input
- Textareas: same styling, monospace font for YAML/code inputs

### Fieldsets

- Border: `--border`
- Border-radius: 6px
- Legend: 600 weight, `--text-secondary`
- Hint text: `--muted`, 12px

### Notices

| Type | Background | Border | Text |
|------|-----------|--------|------|
| Success | `--success-bg` | `--success-border` | `--success` |
| Error | `--danger-bg` | `--danger-border` | `--danger` |

### Login Page

- Centered card (max-width 420px) with `--panel` background
- Title in `--primary` (cyan)
- Same form input styling as above
- Subtle panel border glow

## JavaScript Additions

### Confirmation Dialogs

Small inline script at the bottom of `_page()`. Intercepts form submissions for destructive actions (delete, rotate, disable) and shows a styled modal. Falls back to native `confirm()` if JS is disabled.

```
Forms with class "confirm-action" get intercepted.
Data attributes: data-confirm-title, data-confirm-message
Modal structure: overlay + centered panel with Cancel/Confirm buttons.
```

### Inline Form Validation

Required fields (`required` attribute) get validated on blur and on submit. Adds/removes an error message `<div>` below the input and toggles the invalid border style. No external library — ~30 lines of vanilla JS.

## Transitions & Polish

- Button hover: `filter: brightness(1.15)`, 150ms transition
- Table row hover: background transition, 150ms
- Nav link hover: color transition to `--primary`, 150ms
- Notice: `animation: fadeIn 0.2s ease-out`
- Modal: `animation: fadeIn 0.15s ease-out` on overlay and panel
- Input focus: border-color + box-shadow transition, 150ms

## Responsive Behavior

- Max-width: 1180px centered (unchanged)
- Stats cards: `grid-template-columns: repeat(auto-fit, minmax(200px, 1fr))` — collapses to 2x2 then 1-column on mobile
- Mobile breakpoint at 760px: stacked toolbar, horizontal-scroll tables, full-width buttons
- Nav links wrap or collapse on smaller screens

## Pages Affected

All pages rendered by `ui.py`:

1. **Login** (`_login_page`) — dark card, cyan title
2. **Change Password** (`_change_password_page`) — same treatment as login
3. **Policies Index** (`policies_index`) — stats cards + enhanced table
4. **Policy Form** (`_policy_form`) — dark form inputs, validation
5. **Clients Index** (`clients_index`) — enhanced table
6. **Client Form** (`_client_form`) — dark form inputs, fieldsets, validation
7. **Violations** (`violations_index`) — stats cards + two enhanced tables
8. **Settings** (`settings_page`) — dark form inputs, fieldsets

## Implementation Scope

All changes are within `rampart/app/ui.py`:

1. Replace CSS variables and all styles in `_page()` style block
2. Update `_page()` HTML: header markup, add `<script>` block
3. Update `_policy_row()` and `_client_row()`: severity badges, button classes
4. Add `_stats_cards()` helper for policies index
5. Add `_violation_stats_cards()` helper for violations page
6. Update `_notice()`: new color scheme
7. Update `_login_page()` and `_change_password_page()`: dark card styling
8. Update `_settings_form()` and `_client_form()`: input/fieldset styling
9. Add confirmation `data-` attributes to delete/rotate/disable forms
10. Add severity-to-color mapping helper `_severity_class()`

No changes to routing, form handling, data models, or backend logic.
