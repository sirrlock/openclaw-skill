# @sirrlock/openclaw-skill

[![npm version](https://img.shields.io/npm/v/@sirrlock/openclaw-skill)](https://www.npmjs.com/package/@sirrlock/openclaw-skill)
[![npm downloads](https://img.shields.io/npm/dm/@sirrlock/openclaw-skill)](https://www.npmjs.com/package/@sirrlock/openclaw-skill)
[![CI](https://github.com/sirrlock/openclaw-skill/actions/workflows/ci.yml/badge.svg)](https://github.com/sirrlock/openclaw-skill/actions)
[![TypeScript](https://img.shields.io/badge/TypeScript-5-blue)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/node-%3E%3D18-brightgreen)](https://nodejs.org)
[![Bundle size](https://img.shields.io/bundlephobia/min/@sirrlock/openclaw-skill)](https://bundlephobia.com/package/@sirrlock/openclaw-skill)
[![GitHub stars](https://img.shields.io/github/stars/sirrlock/openclaw-skill)](https://github.com/sirrlock/openclaw-skill)
[![Last commit](https://img.shields.io/github/last-commit/sirrlock/openclaw-skill)](https://github.com/sirrlock/openclaw-skill)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

OpenClaw workspace skill for [Sirr](https://sirrlock.com) — the ephemeral secret manager.

## Installation

```bash
npm install @sirrlock/openclaw-skill
```

Add to your OpenClaw workspace:

```js
// openclaw.config.js
module.exports = {
  skills: ["@sirrlock/openclaw-skill"]
};
```

## Configuration

| Field | Description | Default |
|-------|-------------|---------|
| `serverUrl` | Base URL of your Sirr server | `http://localhost:39999` |
| `token` | Bearer token (master key or scoped API key) | — |
| `org` | Organization slug for multi-tenant mode (optional) | — |

When `org` is set, all API calls are scoped to `/orgs/{org}/...` endpoints.

## Triggers

The skill activates on keywords: `secret`, `sirr`, `credential`, `burn after read`, `ephemeral`, `api key`, `vault`.

## Operations

| Category | Operations |
|----------|-----------|
| Secrets | `getSecret`, `checkSecret`, `pushSecret`, `listSecrets`, `patchSecret`, `deleteSecret`, `pruneSecrets` |
| Audit | `queryAudit` |
| Webhooks | `createWebhook`, `listWebhooks`, `deleteWebhook` |
| Keys | `createKey`, `deleteKey` (list via `getMe`) |
| Me | `getMe`, `patchMe` |
| Orgs | `createOrg`, `listOrgs`, `deleteOrg` |
| Principals | `createPrincipal`, `listPrincipals`, `deletePrincipal` |
| Roles | `createRole`, `listRoles`, `deleteRole` |
| Server | `healthCheck` |

## Multi-Tenant Support

Set the `org` config field to your organization slug to scope all operations to that org:

```js
// openclaw.config.js
module.exports = {
  skills: [{
    name: "@sirrlock/openclaw-skill",
    config: {
      serverUrl: "https://sirr.example.com",
      token: "sk_...",
      org: "my-team"
    }
  }]
};
```

With `org: "my-team"`, requests route to `/orgs/my-team/secrets`, `/orgs/my-team/audit`, etc.
Without `org`, requests use the default single-tenant paths (`/secrets`, `/audit`, etc.).

## Documentation

Full guide at [sirrlock.com/docs/openclaw](https://sirrlock.com/docs/openclaw).

## License

MIT — see [LICENSE](LICENSE).
