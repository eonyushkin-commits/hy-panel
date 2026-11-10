---
name: hy-panel
description: Minimal monochrome operator panel with selective monospace typography.
colors:
  bg: "#fafafa"
  surface: "#fff"
  surface-2: "#f1f1f1"
  fg: "#202020"
  mute: "#686868"
  line: "#e2e2e2"
  acc: "#b74b26"
  acc-soft: "#b74b2610"
  on-acc: "#fff"
  ok: "#23754a"
  ok-soft: "#23754a12"
  bad: "#bb3535"
  on-bad: "#fff"
  bad-soft: "#bb353512"
  warn: "#945900"
  warn-soft: "#94590012"
  dark-bg: "#111"
  dark-surface: "#171717"
  dark-surface-2: "#202020"
  dark-fg: "#eaeaea"
  dark-mute: "#a0a0a0"
  dark-line: "#303030"
  dark-acc: "#e9a17b"
  dark-acc-soft: "#e9a17b14"
  dark-on-acc: "#281c15"
  dark-ok: "#83c9a0"
  dark-ok-soft: "#83c9a012"
  dark-bad: "#f28e8e"
  dark-on-bad: "#111"
  dark-bad-soft: "#f28e8e14"
  dark-warn: "#e5bd77"
  dark-warn-soft: "#e5bd7714"
  backdrop: "#090d0ba8"
typography:
  headline:
    fontSize: "22px"
    fontWeight: 550
    lineHeight: 1.2
    letterSpacing: "-.035em"
  title:
    fontSize: "16px"
    fontWeight: 650
    letterSpacing: "-.01em"
  body:
    fontFamily: 'ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif'
    fontSize: "14px"
    lineHeight: 1.5
  label:
    fontSize: "12.5px"
  metric:
    fontFamily: 'ui-monospace, "Cascadia Code", "SFMono-Regular", Consolas, "Liberation Mono", monospace'
    fontSize: "26px"
    fontWeight: 500
    lineHeight: 1.2
    letterSpacing: "-.04em"
  mono:
    fontFamily: 'ui-monospace, "Cascadia Code", "SFMono-Regular", Consolas, "Liberation Mono", monospace'
    fontSize: "12px"
    lineHeight: 1.5
rounded:
  r-sm: "6px"
  r: "12px"
  dialog: "16px"
  avatar: "6px"
  progress: "2px"
  pill: "99px"
spacing:
  control-gap: "8px"
  grid-gap: "12px"
  row-gap: "16px"
  dialog-padding: "24px"
  desktop-gutter: "32px"
  mobile-gutter: "20px"
  narrow-gutter: "16px"
components:
  button-primary:
    backgroundColor: "{colors.fg}"
    textColor: "{colors.bg}"
    rounded: "{rounded.r-sm}"
    padding: "8px 13px"
  input:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.fg}"
    rounded: "{rounded.r-sm}"
    padding: "8px 10px"
  card:
    backgroundColor: "{colors.surface}"
    rounded: "{rounded.r}"
  pill-warning:
    backgroundColor: "{colors.warn-soft}"
    textColor: "{colors.warn}"
    rounded: "{rounded.pill}"
    padding: "1px 8px"
---

# Design System: hy-panel

## Overview

Minimal and neat is the approved direction. This compact VPN operator workspace uses grayscale hierarchy, open rows and selective monospace to make users, traffic and protocol states easy to scan. Branding is a text wordmark with the default globe removed. The implementation remains one embedded `index.html`, with system fonts, inline functional SVG icons, no external assets and no frontend build.

Key characteristics: flat dividers, monochrome primary actions, aligned data columns, explicit operational states, light and dark themes.

## Colors

Neutral grayscale is the default. Primary buttons invert foreground and page background. Warm orange marks focus, selection, carets and focused/hovered help affordances. Ordinary quota progress is muted gray. Green means enabled or healthy, amber warning or stale, and red error, stopped or destructive. Soft semantic fills accompany pills and notices; retain accompanying state text.

Unprefixed frontmatter tokens describe light mode; `dark-*` records dark values. CSS retains the same variable names in both themes. Error toasts use `on-bad` for contrast. Initial theme follows the operating system unless an explicit choice is saved. The header control persists light/dark selection and matching native control color scheme.

## Typography

System sans remains the operating UI: body 14px/1.5, overview 22px at weight 550, user section 16px at weight 600 and secondary labels 11–12.5px. The actual `--mono` stack supplies the wordmark (18px, weight 500), host (12px), tabular metrics (26px, weight 500), protocol details/ports (11px), traffic (13px with 11px detail), configuration and logs (12px). The login wordmark is 22px. Metrics use -.04em tracking.

At 640px wordmark becomes 16px, host 10px and metrics 22px. At 360px metrics become 17px. Use monospace for identifiers and quantitative content while retaining sans for labels and actions. Compactness comes primarily from spacing, not shrinking body text or controls.

## Layout

`main` is centered with a 1120px maximum width, 32px horizontal and bottom padding. Header minimum height is 60px with a bottom divider and 24px bottom margin. The overview has one heading and its primary action, without a supporting description. Statistics are three unboxed columns with internal dividers and a shared bottom rule; they have no metric icons, 6px between labels and numbers and 16px bottom padding. Protocols are two flat columns with no gap, a dividing rule, top/bottom borders and 12px vertical padding; they stack at 760px.

Desktop user rows and header use `minmax(0,1fr) 220px 198px` columns for identity, traffic and actions, with 24px gaps. At 900px traffic/actions become 180px with 16px gaps. Rows use horizontal dividers rather than separate cards, with 12px vertical padding and 8px for column headings. Search sits to the right of underline filters on desktop; the toolbar uses 12px vertical padding. Separate the user section from protocols by 24px. A representative three-user list fits a 900px-high desktop viewport without scrolling; longer lists and alerts grow naturally.

At 640px gutters become 20px, bottom padding 24px and header minimum height 64px. Search precedes full-width filters. User rows stack identity, traffic and actions, with 14px vertical padding and 8px internal gaps; traffic/actions indent 46px under text and controls retain 44px-high touch areas. At 360px gutters become 16px and actions lose the indent. Dialog forms use two columns with a 12px gap, becoming one at 480px. Normal dialogs are at most 480px wide, sharing at most 640px, both retaining 12px viewport side margins. Long identifiers and configuration wrap.

## Elevation & Depth

Page hierarchy is flat: whitespace, dividers and restrained tones provide separation. Remaining card surfaces and sharing segments use `--shadow:none`. Dialogs, tooltips and toasts use light `0 24px 80px -16px #171b2340` or dark `0 24px 80px -16px #000a`. A dim backdrop separates modal work. Switch knobs use `0 1px 2px #0004`.

## Shapes

Controls use 6px corners, remaining card surfaces 12px, dialogs 16px and avatars 6px. QR frames use 12px. Pills and switches are capsules; progress is 3px high with 2px corners. Borders are 1px. Functional icons are typically 16px line SVGs with 2px strokes; there is no globe or logo asset.

## Components

- **Buttons:** 38px minimum height, 8px 13px padding, 8px gaps. Primary actions use foreground fill and page-background text; hover opacity is .88. Secondary buttons use surface and border; ghost actions have no resting fill. Active presses scale to .97, disabled controls fade to .55. Destructive icon hover uses red semantic fill.
- **Fields:** surface fill, 1px border, 8px 10px padding. Placeholders use muted text at full opacity. Hover changes border to muted text. Keyboard focus uses a 2px accent outline with 3px offset across controls and links.
- **Filters and sharing tabs:** user filters have no tray; selected filters use a 2px foreground underline, weight 550 and `aria-pressed`. Sharing segments retain the muted tray with surface-filled selection.
- **User rows:** neutral initials, online/stale dots, textual pills, separate traffic column and grouped actions. Fine-pointer hover adds a faint neutral tint. Quota progress is gray until warning/error thresholds. Data refresh has no list choreography.
- **Protocol rows:** title and dot pair with explicit state text, monospace details and wrapping actions. Preserve unavailable, stale, stopped and unconfigured distinctions.
- **Dialogs and feedback:** opacity and scale .97 to 1 transition over 200ms with `cubic-bezier(.23,1,.32,1)`; backdrop fades with them. Toasts use the same timing with a 6px entrance translation. Switch transitions use 160ms. Reduced-motion preference disables all transitions and animations. Keep existing browser dialog, form and top-layer toast behavior.

## Do's and Don'ts

- **Do** preserve state wording, keyboard focus, aligned traffic, mobile wrapping and both themes.
- **Do** keep monochrome actions, flat dividers and selective system monospace.
- **Don't** restore the default globe or decorate metrics with icons.
- **Don't** turn warm orange into broad button/progress fill or substitute it for semantic states.
- **Don't** add decorative list choreography, external fonts or external assets.
