# @sirrlock/openclaw-skill — Claude Development Guide

## Purpose

OpenClaw workspace skill for Sirr — the ephemeral secret manager. Wraps the
Sirr REST API as callable functions, triggered by natural language keywords.

## Stack

- TypeScript, compiled to ESM
- Zero dependencies (uses native fetch)

## Build

```bash
npm install
npm run build    # tsc → dist/
```

## Structure

```
skill.json        # OpenClaw manifest: name, triggers, config schema
src/index.ts      # HTTP client wrapping the full Sirr API surface
```

## API Coverage

Full Sirr API surface — 24 operations across 7 groups:

- **Secrets**: getSecret, pushSecret, listSecrets, patchSecret, deleteSecret, pruneSecrets
- **Audit**: queryAudit
- **Webhooks**: createWebhook, listWebhooks, deleteWebhook
- **Keys** (`/me/keys`): createKey, deleteKey
- **Me** (`/me`): getMe, patchMe
- **Orgs**: createOrg, listOrgs, deleteOrg
- **Principals**: createPrincipal, listPrincipals, deletePrincipal
- **Roles**: createRole, listRoles, deleteRole
- **Server**: healthCheck

Public-bucket operations (`/secrets/*`, `/audit`, `/webhooks`, `/prune`) are automatically
routed to org-scoped equivalents (`/orgs/{org_id}/...`) when `config.org` is set.

## Key Rules

- Health check does NOT send auth headers (`auth = false`)
- Secret key names and IDs are URL-encoded in path params
- `ttl_seconds` and `max_reads` accept `null` for "no limit"
- `pushSecret` `delete` field: `true` (default) = burn on expiry, `false` = seal (patchable)
- `patchSecret` only works on secrets created with `delete: false`
- Key creation accepts `valid_for_seconds` (relative) OR `valid_before` (absolute Unix timestamp)
- `createKey` returns the raw key once — must be saved immediately
- `createWebhook` returns the signing secret once — must be saved immediately
- `getMe` includes the `keys` array — there is no separate list-keys endpoint
- Org management (createOrg, createPrincipal, createRole, deleteOrg/Principal/Role) requires master key
- `getMe` / `createKey` / `deleteKey` require a principal key (master key is rejected)

## Route Map

| Function | Method | Path |
|---|---|---|
| `healthCheck` | GET | `/health` |
| `getSecret` | GET | `/secrets/:key` or `/orgs/:org/secrets/:key` |
| `pushSecret` | POST | `/secrets` or `/orgs/:org/secrets` |
| `listSecrets` | GET | `/secrets` or `/orgs/:org/secrets` |
| `patchSecret` | PATCH | `/secrets/:key` or `/orgs/:org/secrets/:key` |
| `deleteSecret` | DELETE | `/secrets/:key` or `/orgs/:org/secrets/:key` |
| `pruneSecrets` | POST | `/prune` or `/orgs/:org/prune` |
| `queryAudit` | GET | `/audit` or `/orgs/:org/audit` |
| `createWebhook` | POST | `/webhooks` or `/orgs/:org/webhooks` |
| `listWebhooks` | GET | `/webhooks` or `/orgs/:org/webhooks` |
| `deleteWebhook` | DELETE | `/webhooks/:id` or `/orgs/:org/webhooks/:id` |
| `createKey` | POST | `/me/keys` |
| `deleteKey` | DELETE | `/me/keys/:keyId` |
| `getMe` | GET | `/me` |
| `patchMe` | PATCH | `/me` |
| `createOrg` | POST | `/orgs` |
| `listOrgs` | GET | `/orgs` |
| `deleteOrg` | DELETE | `/orgs/:orgId` |
| `createPrincipal` | POST | `/orgs/:orgId/principals` |
| `listPrincipals` | GET | `/orgs/:orgId/principals` |
| `deletePrincipal` | DELETE | `/orgs/:orgId/principals/:id` |
| `createRole` | POST | `/orgs/:orgId/roles` |
| `listRoles` | GET | `/orgs/:orgId/roles` |
| `deleteRole` | DELETE | `/orgs/:orgId/roles/:name` |
