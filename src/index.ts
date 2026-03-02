/**
 * @sirrlock/openclaw-skill
 *
 * OpenClaw workspace skill wrapping the Sirr REST API.
 * Covers the full API surface: secrets, audit, webhooks, keys,
 * identity (/me), and multi-tenant org/principal/role management.
 */

export interface SirrConfig {
  /** Base URL of your Sirr server, e.g. "http://localhost:39999" */
  serverUrl: string;
  /** Master key or principal API key */
  token: string;
  /** Org ID for multi-tenant mode. When set, secret/audit/webhook
   *  operations are scoped to this org. */
  org?: string;
}

/* ── Internal helpers ────────────────────────────────────────── */

function base(config: SirrConfig): string {
  return config.serverUrl.replace(/\/+$/, '');
}

function secretsPath(config: SirrConfig, key?: string): string {
  const prefix = config.org ? `/orgs/${config.org}/secrets` : '/secrets';
  return key ? `${prefix}/${encodeURIComponent(key)}` : prefix;
}

function auditPath(config: SirrConfig): string {
  return config.org ? `/orgs/${config.org}/audit` : '/audit';
}

function webhooksPath(config: SirrConfig, id?: string): string {
  const prefix = config.org ? `/orgs/${config.org}/webhooks` : '/webhooks';
  return id ? `${prefix}/${encodeURIComponent(id)}` : prefix;
}

function prunePath(config: SirrConfig): string {
  return config.org ? `/orgs/${config.org}/prune` : '/prune';
}

async function call(
  config: SirrConfig,
  method: string,
  path: string,
  body?: unknown,
  auth = true,
): Promise<unknown> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (auth) headers['Authorization'] = `Bearer ${config.token}`;

  const res = await fetch(`${base(config)}${path}`, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });

  if (res.status === 204) return undefined;

  const payload = await res.json().catch(() => ({ error: res.statusText }));

  if (!res.ok) {
    const msg = (payload as { error?: string; message?: string }).error
      ?? (payload as { message?: string }).message
      ?? res.statusText;
    throw new Error(`Sirr ${method} ${path} (${res.status}): ${msg}`);
  }

  return payload;
}

/* ── Response types ──────────────────────────────────────────── */

export interface SecretMeta {
  key: string;
  created_at: number;
  expires_at: number | null;
  max_reads: number | null;
  read_count: number;
  /** true = burns on expiry, false = seals (patchable) */
  delete?: boolean;
}

export interface SecretValue extends SecretMeta {
  value: string;
}

/** Metadata returned by HEAD /secrets/{key} — no read counter increment. */
export interface SecretStatus {
  status: 'active' | 'sealed';
  read_count: number;
  reads_remaining: number | 'unlimited';
  delete: boolean;
  created_at: number;
  /** Absent if the secret has no expiry. */
  expires_at?: number;
}

export interface AuditEvent {
  id: number;
  timestamp: number;
  action: string;
  key: string | null;
  source_ip: string;
  success: boolean;
}

export interface Webhook {
  id: string;
  url: string;
  events: string[];
  created_at: number;
}

export interface PrincipalKey {
  id: string;
  name: string;
  valid_after: number;
  valid_before: number;
  created_at: number;
}

export interface Me {
  id: string;
  name: string;
  role: string;
  org_id: string;
  metadata: Record<string, string>;
  created_at: number;
  keys: PrincipalKey[];
}

export interface Org {
  id: string;
  name: string;
  created_at: number;
}

export interface Principal {
  id: string;
  name: string;
  role: string;
  org_id: string;
  metadata: Record<string, string>;
  created_at: number;
}

export interface Role {
  name: string;
  permissions: string;
  built_in: boolean;
  org_id: string;
  created_at: number;
}

/* ── Secrets ─────────────────────────────────────────────────── */

/** Retrieve and decrypt a secret. Increments the read counter.
 *  Returns null if the secret has expired, been burned, sealed (410), or doesn't exist. */
export async function getSecret(
  config: SirrConfig,
  key: string,
): Promise<SecretValue | null> {
  const res = await fetch(
    `${base(config)}${secretsPath(config, key)}`,
    { headers: { 'Authorization': `Bearer ${config.token}` } },
  );
  if (res.status === 404 || res.status === 410) return null;
  const payload = await res.json().catch(() => ({ error: res.statusText }));
  if (!res.ok) {
    const msg = (payload as { error?: string; message?: string }).error
      ?? (payload as { message?: string }).message
      ?? res.statusText;
    throw new Error(`Sirr GET ${secretsPath(config, key)} (${res.status}): ${msg}`);
  }
  return payload as SecretValue;
}

/** Inspect a secret's metadata without incrementing the read counter.
 *  Returns null if the secret doesn't exist (404) or is sealed/burned (410).
 *  Use this to verify a secret is still valid before fetching it. */
export async function checkSecret(
  config: SirrConfig,
  key: string,
): Promise<SecretStatus | null> {
  const path = secretsPath(config, key);
  const res = await fetch(`${base(config)}${path}`, {
    method: 'HEAD',
    headers: { 'Authorization': `Bearer ${config.token}` },
  });
  if (res.status === 404 || res.status === 410) return null;
  if (!res.ok) {
    throw new Error(`Sirr HEAD ${path} (${res.status}): ${res.statusText}`);
  }
  const readsRemaining = res.headers.get('X-Sirr-Reads-Remaining');
  return {
    status: res.headers.get('X-Sirr-Status') as 'active' | 'sealed',
    read_count: parseInt(res.headers.get('X-Sirr-Read-Count') ?? '0', 10),
    reads_remaining: readsRemaining === 'unlimited'
      ? 'unlimited'
      : parseInt(readsRemaining ?? '0', 10),
    delete: res.headers.get('X-Sirr-Delete') === 'true',
    created_at: parseInt(res.headers.get('X-Sirr-Created-At') ?? '0', 10),
    ...(res.headers.get('X-Sirr-Expires-At') != null && {
      expires_at: parseInt(res.headers.get('X-Sirr-Expires-At')!, 10),
    }),
  };
}

/** Store a new secret with optional TTL and read limit.
 *  Set `delete: false` to keep the record sealed (patchable) instead of
 *  burning it when max_reads is reached.
 *  Set `allowed_keys` to restrict which principal key names can read this secret (org-scoped only). */
export async function pushSecret(
  config: SirrConfig,
  params: {
    key: string;
    value: string;
    ttl_seconds?: number | null;
    max_reads?: number | null;
    /** false = seal on expiry (secret stays, reads blocked, patchable).
     *  true (default) = burn on expiry. */
    delete?: boolean;
    /** Restrict reads to these principal key names. Absent = any key can read. Org-scoped only. */
    allowed_keys?: string[];
  },
): Promise<{ key: string }> {
  return call(config, 'POST', secretsPath(config), params) as Promise<{ key: string }>;
}

/** List metadata for all active secrets. Values are never included. */
export async function listSecrets(config: SirrConfig): Promise<SecretMeta[]> {
  const res = await call(config, 'GET', secretsPath(config)) as { secrets: SecretMeta[] };
  return res.secrets;
}

/** Update a secret's TTL, read limit, or value.
 *  Only works on secrets created with `delete: false` (sealable secrets). */
export async function patchSecret(
  config: SirrConfig,
  key: string,
  params: {
    value?: string;
    ttl_seconds?: number;
    max_reads?: number;
  },
): Promise<{ key: string; updated: boolean }> {
  return call(
    config,
    'PATCH',
    secretsPath(config, key),
    params,
  ) as Promise<{ key: string; updated: boolean }>;
}

/** Permanently delete a secret immediately. */
export async function deleteSecret(
  config: SirrConfig,
  key: string,
): Promise<{ deleted: boolean }> {
  return call(config, 'DELETE', secretsPath(config, key)) as Promise<{ deleted: boolean }>;
}

/** Remove all expired secrets. Returns the count of pruned records. */
export async function pruneSecrets(
  config: SirrConfig,
): Promise<{ pruned: number }> {
  return call(config, 'POST', prunePath(config)) as Promise<{ pruned: number }>;
}

/* ── Audit ───────────────────────────────────────────────────── */

/** Query the audit log. Supports filtering by timestamp, action, and limit. */
export async function queryAudit(
  config: SirrConfig,
  params?: {
    since?: number;
    until?: number;
    action?: string;
    limit?: number;
  },
): Promise<AuditEvent[]> {
  const qs = new URLSearchParams();
  if (params?.since != null) qs.set('since', String(params.since));
  if (params?.until != null) qs.set('until', String(params.until));
  if (params?.action) qs.set('action', params.action);
  if (params?.limit != null) qs.set('limit', String(params.limit));
  const query = qs.toString();
  const path = `${auditPath(config)}${query ? `?${query}` : ''}`;
  const res = await call(config, 'GET', path) as { events: AuditEvent[] };
  return res.events;
}

/* ── Webhooks ────────────────────────────────────────────────── */

/** Register a webhook endpoint. Returns the signing secret — save it immediately. */
export async function createWebhook(
  config: SirrConfig,
  params: {
    url: string;
    events?: string[];
  },
): Promise<{ id: string; secret: string }> {
  return call(config, 'POST', webhooksPath(config), params) as Promise<{ id: string; secret: string }>;
}

/** List all registered webhooks. */
export async function listWebhooks(config: SirrConfig): Promise<Webhook[]> {
  const res = await call(config, 'GET', webhooksPath(config)) as { webhooks: Webhook[] };
  return res.webhooks;
}

/** Remove a webhook by ID. */
export async function deleteWebhook(
  config: SirrConfig,
  id: string,
): Promise<{ deleted: boolean }> {
  return call(config, 'DELETE', webhooksPath(config, id)) as Promise<{ deleted: boolean }>;
}

/* ── Keys (/me/keys) ─────────────────────────────────────────── */

/** Create a new API key for the authenticated principal.
 *  The raw key is returned once — save it immediately.
 *  Use `valid_before` (Unix timestamp) or `valid_for_seconds` for time-windowed keys. */
export async function createKey(
  config: SirrConfig,
  params: {
    name: string;
    valid_for_seconds?: number;
    valid_before?: number;
  },
): Promise<{ id: string; name: string; key: string; valid_after: number; valid_before: number }> {
  return call(
    config,
    'POST',
    '/me/keys',
    params,
  ) as Promise<{ id: string; name: string; key: string; valid_after: number; valid_before: number }>;
}

/** Permanently revoke one of the authenticated principal's keys. */
export async function deleteKey(
  config: SirrConfig,
  keyId: string,
): Promise<{ deleted: boolean }> {
  return call(
    config,
    'DELETE',
    `/me/keys/${encodeURIComponent(keyId)}`,
  ) as Promise<{ deleted: boolean }>;
}

/* ── Me ──────────────────────────────────────────────────────── */

/** Return the authenticated principal's identity, org, role, permissions,
 *  and all their active keys. */
export async function getMe(config: SirrConfig): Promise<Me> {
  return call(config, 'GET', '/me') as Promise<Me>;
}

/** Update the authenticated principal's metadata. */
export async function patchMe(
  config: SirrConfig,
  metadata: Record<string, string>,
): Promise<{ updated: boolean }> {
  return call(config, 'PATCH', '/me', { metadata }) as Promise<{ updated: boolean }>;
}

/* ── Orgs ────────────────────────────────────────────────────── */

/** Create a new organization. Requires master key. */
export async function createOrg(
  config: SirrConfig,
  params: {
    name: string;
    metadata?: Record<string, string>;
  },
): Promise<Org> {
  return call(config, 'POST', '/orgs', params) as Promise<Org>;
}

/** List all organizations. Requires master key. */
export async function listOrgs(config: SirrConfig): Promise<Org[]> {
  const res = await call(config, 'GET', '/orgs') as { orgs: Org[] };
  return res.orgs;
}

/** Delete an organization. The org must have no principals. Requires master key. */
export async function deleteOrg(
  config: SirrConfig,
  orgId: string,
): Promise<{ deleted: boolean }> {
  return call(config, 'DELETE', `/orgs/${encodeURIComponent(orgId)}`) as Promise<{ deleted: boolean }>;
}

/* ── Principals ──────────────────────────────────────────────── */

/** Create a principal (user or service account) within an org. Requires master key. */
export async function createPrincipal(
  config: SirrConfig,
  orgId: string,
  params: {
    name: string;
    role: string;
    metadata?: Record<string, string>;
  },
): Promise<Principal> {
  return call(
    config,
    'POST',
    `/orgs/${encodeURIComponent(orgId)}/principals`,
    params,
  ) as Promise<Principal>;
}

/** List all principals in an org. */
export async function listPrincipals(
  config: SirrConfig,
  orgId: string,
): Promise<Principal[]> {
  const res = await call(
    config,
    'GET',
    `/orgs/${encodeURIComponent(orgId)}/principals`,
  ) as { principals: Principal[] };
  return res.principals;
}

/** Delete a principal. The principal must have no active keys. Requires master key. */
export async function deletePrincipal(
  config: SirrConfig,
  orgId: string,
  principalId: string,
): Promise<{ deleted: boolean }> {
  return call(
    config,
    'DELETE',
    `/orgs/${encodeURIComponent(orgId)}/principals/${encodeURIComponent(principalId)}`,
  ) as Promise<{ deleted: boolean }>;
}

/* ── Roles ───────────────────────────────────────────────────── */

/** Create a custom role for an org. Requires master key.
 *  `permissions` is a letter string, e.g. "rRlL". Built-in roles cannot be overwritten. */
export async function createRole(
  config: SirrConfig,
  orgId: string,
  params: {
    name: string;
    permissions: string;
  },
): Promise<Role> {
  return call(
    config,
    'POST',
    `/orgs/${encodeURIComponent(orgId)}/roles`,
    params,
  ) as Promise<Role>;
}

/** List all roles (built-in and custom) for an org. */
export async function listRoles(
  config: SirrConfig,
  orgId: string,
): Promise<Role[]> {
  const res = await call(
    config,
    'GET',
    `/orgs/${encodeURIComponent(orgId)}/roles`,
  ) as { roles: Role[] };
  return res.roles;
}

/** Delete a custom role. Built-in roles cannot be deleted. Requires master key. */
export async function deleteRole(
  config: SirrConfig,
  orgId: string,
  roleName: string,
): Promise<{ deleted: boolean }> {
  return call(
    config,
    'DELETE',
    `/orgs/${encodeURIComponent(orgId)}/roles/${encodeURIComponent(roleName)}`,
  ) as Promise<{ deleted: boolean }>;
}

/* ── Server ──────────────────────────────────────────────────── */

/** Check whether the Sirr server is reachable. No auth required. */
export async function healthCheck(config: SirrConfig): Promise<{ status: string }> {
  return call(config, 'GET', '/health', undefined, false) as Promise<{ status: string }>;
}
