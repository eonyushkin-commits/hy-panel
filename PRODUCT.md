# hy-panel

<!-- impeccable:product-schema 1 -->

## Platform

web

## Product Purpose

Manage Hysteria 2 and VLESS/Reality VPN access from a compact browser interface.
Product facts below come from README.md and the existing implementation; the
administrator audience is inferred from the available operations.

## Capabilities and Constraints

- Show users, unique users online, traffic and freshness of protocol polling.
- Create, edit, disable and delete users; manage quotas, expiry and protocol access.
- Share credentials, QR codes and subscriptions, including Mihomo configurations.
- Install, configure and update protocol servers through the existing agent.
- Preserve explicit unavailable, stale, stopped and unconfigured states.
- Keep a single embedded index.html with no frontend build or external assets.
- Support narrow mobile screens, keyboard operation and both color schemes.

## Evidence on Hand

README.md, index.html, tests/ui/*.cjs and the Go backend. Preview fixtures are
illustrative and must never be shown as actual server data.
