import { beforeEach, describe, expect, it, jest } from '@jest/globals';
import {
  checkSecret,
  createKey,
  createOrg,
  createPrincipal,
  createRole,
  createWebhook,
  deleteKey,
  deleteOrg,
  deletePrincipal,
  deleteRole,
  deleteSecret,
  deleteWebhook,
  getMe,
  getSecret,
  healthCheck,
  listOrgs,
  listPrincipals,
  listRoles,
  listSecrets,
  listWebhooks,
  patchMe,
  patchSecret,
  pruneSecrets,
  pushSecret,
  queryAudit,
} from './index';
import type { SirrConfig } from './index';

/* ── Fetch mock setup ────────────────────────────────────── */

const mockFetch = jest.fn<typeof fetch>();
global.fetch = mockFetch;

const cfg: SirrConfig = {
  serverUrl: 'http://localhost:39999',
  token: 'test-token',
};

const orgCfg: SirrConfig = { ...cfg, org: 'org_abc123' };

function ok(body: unknown, status = 200): Response {
  return {
    ok: true,
    status,
    json: () => Promise.resolve(body),
  } as unknown as Response;
}

function fail(status: number, body: unknown): Response {
  return {
    ok: false,
    status,
    statusText: 'Error',
    json: () => Promise.resolve(body),
  } as unknown as Response;
}

function failText(status: number, text: string): Response {
  return {
    ok: false,
    status,
    statusText: text,
    json: () => Promise.reject(new SyntaxError('non-json')),
  } as unknown as Response;
}

function notFound(): Response {
  return {
    ok: false,
    status: 404,
    statusText: 'Not Found',
    json: () => Promise.resolve({ error: 'not found' }),
  } as unknown as Response;
}

function gone(): Response {
  return {
    ok: false,
    status: 410,
    statusText: 'Gone',
    json: () => Promise.resolve({ error: 'sealed' }),
  } as unknown as Response;
}

function headOk(headers: Record<string, string>): Response {
  return {
    ok: true,
    status: 200,
    statusText: 'OK',
    headers: { get: (name: string) => headers[name] ?? null },
  } as unknown as Response;
}

beforeEach(() => { mockFetch.mockReset(); });

function lastCall() {
  const [url, init] = mockFetch.mock.calls[0] as [string, RequestInit];
  const body = init?.body ? JSON.parse(init.body as string) : undefined;
  return { url, method: init?.method ?? 'GET', headers: init?.headers as Record<string, string>, body };
}

/* ── healthCheck ─────────────────────────────────────────── */

describe('healthCheck', () => {
  it('GETs /health with no auth header', async () => {
    mockFetch.mockResolvedValueOnce(ok({ status: 'ok' }));
    const res = await healthCheck(cfg);
    const { url, headers } = lastCall();
    expect(url).toBe('http://localhost:39999/health');
    expect(headers?.['Authorization']).toBeUndefined();
    expect(res.status).toBe('ok');
  });
});

/* ── getSecret ───────────────────────────────────────────── */

describe('getSecret', () => {
  it('GETs /secrets/:key with auth', async () => {
    mockFetch.mockResolvedValueOnce(ok({ key: 'DB_URL', value: 'postgres://...' }));
    const res = await getSecret(cfg, 'DB_URL');
    const { url, headers } = lastCall();
    expect(url).toBe('http://localhost:39999/secrets/DB_URL');
    expect(headers?.['Authorization']).toBe('Bearer test-token');
    expect(res?.value).toBe('postgres://...');
  });

  it('URL-encodes the key', async () => {
    mockFetch.mockResolvedValueOnce(ok({ key: 'a b', value: 'v' }));
    await getSecret(cfg, 'a b');
    expect(lastCall().url).toBe('http://localhost:39999/secrets/a%20b');
  });

  it('routes to org path when config.org is set', async () => {
    mockFetch.mockResolvedValueOnce(ok({ key: 'K', value: 'v' }));
    await getSecret(orgCfg, 'K');
    expect(lastCall().url).toBe('http://localhost:39999/orgs/org_abc123/secrets/K');
  });

  it('returns null on 404', async () => {
    mockFetch.mockResolvedValueOnce(notFound());
    const res = await getSecret(cfg, 'missing');
    expect(res).toBeNull();
  });

  it('returns null on 410 (sealed)', async () => {
    mockFetch.mockResolvedValueOnce(gone());
    const res = await getSecret(cfg, 'sealed');
    expect(res).toBeNull();
  });

  it('throws on other errors', async () => {
    mockFetch.mockResolvedValueOnce(fail(500, { error: 'internal error' }));
    await expect(getSecret(cfg, 'K')).rejects.toThrow('500');
  });
});

/* ── checkSecret ─────────────────────────────────────────── */

describe('checkSecret', () => {
  const activeHeaders = {
    'X-Sirr-Status': 'active',
    'X-Sirr-Read-Count': '2',
    'X-Sirr-Reads-Remaining': '3',
    'X-Sirr-Delete': 'true',
    'X-Sirr-Created-At': '1700000000',
    'X-Sirr-Expires-At': '1700003600',
  };

  it('sends HEAD /secrets/:key with auth', async () => {
    mockFetch.mockResolvedValueOnce(headOk(activeHeaders));
    await checkSecret(cfg, 'DB_URL');
    const { url, method, headers } = lastCall();
    expect(method).toBe('HEAD');
    expect(url).toBe('http://localhost:39999/secrets/DB_URL');
    expect(headers?.['Authorization']).toBe('Bearer test-token');
  });

  it('parses response headers into SecretStatus', async () => {
    mockFetch.mockResolvedValueOnce(headOk(activeHeaders));
    const res = await checkSecret(cfg, 'DB_URL');
    expect(res?.status).toBe('active');
    expect(res?.read_count).toBe(2);
    expect(res?.reads_remaining).toBe(3);
    expect(res?.delete).toBe(true);
    expect(res?.created_at).toBe(1700000000);
    expect(res?.expires_at).toBe(1700003600);
  });

  it('parses "unlimited" reads_remaining', async () => {
    mockFetch.mockResolvedValueOnce(headOk({ ...activeHeaders, 'X-Sirr-Reads-Remaining': 'unlimited' }));
    const res = await checkSecret(cfg, 'K');
    expect(res?.reads_remaining).toBe('unlimited');
  });

  it('omits expires_at when header is absent', async () => {
    const { 'X-Sirr-Expires-At': _, ...noExpiry } = activeHeaders;
    mockFetch.mockResolvedValueOnce(headOk(noExpiry));
    const res = await checkSecret(cfg, 'K');
    expect(res?.expires_at).toBeUndefined();
  });

  it('routes to org path when config.org is set', async () => {
    mockFetch.mockResolvedValueOnce(headOk(activeHeaders));
    await checkSecret(orgCfg, 'K');
    expect(lastCall().url).toBe('http://localhost:39999/orgs/org_abc123/secrets/K');
  });

  it('returns null on 404', async () => {
    mockFetch.mockResolvedValueOnce(notFound());
    expect(await checkSecret(cfg, 'missing')).toBeNull();
  });

  it('returns null on 410 (sealed/burned)', async () => {
    mockFetch.mockResolvedValueOnce(gone());
    expect(await checkSecret(cfg, 'burned')).toBeNull();
  });

  it('throws on other errors', async () => {
    mockFetch.mockResolvedValueOnce({ ok: false, status: 500, statusText: 'Internal Server Error', headers: { get: () => null } } as unknown as Response);
    await expect(checkSecret(cfg, 'K')).rejects.toThrow('500');
  });
});

/* ── pushSecret ──────────────────────────────────────────── */

describe('pushSecret', () => {
  it('POSTs to /secrets with all fields', async () => {
    mockFetch.mockResolvedValueOnce(ok({ key: 'K' }, 201));
    await pushSecret(cfg, { key: 'K', value: 'v', ttl_seconds: 3600, max_reads: 1, delete: true });
    const { url, method, body } = lastCall();
    expect(method).toBe('POST');
    expect(url).toBe('http://localhost:39999/secrets');
    expect(body).toMatchObject({ key: 'K', value: 'v', ttl_seconds: 3600, max_reads: 1, delete: true });
  });

  it('routes to org path when config.org is set', async () => {
    mockFetch.mockResolvedValueOnce(ok({ key: 'K' }, 201));
    await pushSecret(orgCfg, { key: 'K', value: 'v' });
    expect(lastCall().url).toBe('http://localhost:39999/orgs/org_abc123/secrets');
  });

  it('sends delete: false for sealable secrets', async () => {
    mockFetch.mockResolvedValueOnce(ok({ key: 'K' }, 201));
    await pushSecret(cfg, { key: 'K', value: 'v', delete: false });
    expect(lastCall().body.delete).toBe(false);
  });

  it('sends allowed_keys when provided', async () => {
    mockFetch.mockResolvedValueOnce(ok({ key: 'K' }, 201));
    await pushSecret(orgCfg, { key: 'K', value: 'v', allowed_keys: ['ci-key', 'deploy-key'] });
    expect(lastCall().body.allowed_keys).toEqual(['ci-key', 'deploy-key']);
  });

  it('throws on non-2xx', async () => {
    mockFetch.mockResolvedValueOnce(fail(402, { error: 'license required' }));
    await expect(pushSecret(cfg, { key: 'K', value: 'v' })).rejects.toThrow('402');
  });
});

/* ── listSecrets ─────────────────────────────────────────── */

describe('listSecrets', () => {
  it('GETs /secrets and returns unwrapped array', async () => {
    mockFetch.mockResolvedValueOnce(ok({ secrets: [] }));
    const res = await listSecrets(cfg);
    expect(lastCall().url).toBe('http://localhost:39999/secrets');
    expect(Array.isArray(res)).toBe(true);
    expect(res).toEqual([]);
  });
});

/* ── patchSecret ─────────────────────────────────────────── */

describe('patchSecret', () => {
  it('PATCHes /secrets/:key with body', async () => {
    mockFetch.mockResolvedValueOnce(ok({ key: 'K', updated: true }));
    const res = await patchSecret(cfg, 'K', { ttl_seconds: 7200 });
    const { url, method, body } = lastCall();
    expect(method).toBe('PATCH');
    expect(url).toBe('http://localhost:39999/secrets/K');
    expect(body).toEqual({ ttl_seconds: 7200 });
    expect(res.updated).toBe(true);
  });

  it('routes to org path when config.org is set', async () => {
    mockFetch.mockResolvedValueOnce(ok({ key: 'K', updated: true }));
    await patchSecret(orgCfg, 'K', { max_reads: 5 });
    expect(lastCall().url).toBe('http://localhost:39999/orgs/org_abc123/secrets/K');
  });

  it('throws on 404', async () => {
    mockFetch.mockResolvedValueOnce(notFound());
    await expect(patchSecret(cfg, 'missing', {})).rejects.toThrow('404');
  });
});

/* ── deleteSecret ────────────────────────────────────────── */

describe('deleteSecret', () => {
  it('DELETEs /secrets/:key', async () => {
    mockFetch.mockResolvedValueOnce(ok({ deleted: true }));
    const res = await deleteSecret(cfg, 'K');
    const { url, method } = lastCall();
    expect(method).toBe('DELETE');
    expect(url).toBe('http://localhost:39999/secrets/K');
    expect(res.deleted).toBe(true);
  });

  it('URL-encodes the key', async () => {
    mockFetch.mockResolvedValueOnce(ok({ deleted: true }));
    await deleteSecret(cfg, 'my key');
    expect(lastCall().url).toContain('my%20key');
  });
});

/* ── pruneSecrets ────────────────────────────────────────── */

describe('pruneSecrets', () => {
  it('POSTs to /prune', async () => {
    mockFetch.mockResolvedValueOnce(ok({ pruned: 3 }));
    const res = await pruneSecrets(cfg);
    const { url, method } = lastCall();
    expect(method).toBe('POST');
    expect(url).toBe('http://localhost:39999/prune');
    expect(res.pruned).toBe(3);
  });

  it('routes to org path when config.org is set', async () => {
    mockFetch.mockResolvedValueOnce(ok({ pruned: 0 }));
    await pruneSecrets(orgCfg);
    expect(lastCall().url).toBe('http://localhost:39999/orgs/org_abc123/prune');
  });
});

/* ── queryAudit ──────────────────────────────────────────── */

describe('queryAudit', () => {
  it('GETs /audit and returns unwrapped array', async () => {
    mockFetch.mockResolvedValueOnce(ok({ events: [] }));
    const res = await queryAudit(cfg);
    expect(lastCall().url).toBe('http://localhost:39999/audit');
    expect(Array.isArray(res)).toBe(true);
    expect(res).toEqual([]);
  });

  it('appends query params', async () => {
    mockFetch.mockResolvedValueOnce(ok({ events: [] }));
    await queryAudit(cfg, { since: 1000, until: 2000, action: 'secret.read', limit: 10 });
    const { url } = lastCall();
    expect(url).toContain('since=1000');
    expect(url).toContain('until=2000');
    expect(url).toContain('action=secret.read');
    expect(url).toContain('limit=10');
  });

  it('routes to org path when config.org is set', async () => {
    mockFetch.mockResolvedValueOnce(ok({ events: [] }));
    await queryAudit(orgCfg);
    expect(lastCall().url).toContain('/orgs/org_abc123/audit');
  });
});

/* ── createWebhook ───────────────────────────────────────── */

describe('createWebhook', () => {
  it('POSTs to /webhooks with url and events', async () => {
    mockFetch.mockResolvedValueOnce(ok({ id: 'wh_1', secret: 's3cr3t' }, 201));
    const res = await createWebhook(cfg, { url: 'https://example.com/hook', events: ['secret.read'] });
    const { url, method, body } = lastCall();
    expect(method).toBe('POST');
    expect(url).toBe('http://localhost:39999/webhooks');
    expect(body).toEqual({ url: 'https://example.com/hook', events: ['secret.read'] });
    expect(res.secret).toBe('s3cr3t');
  });
});

describe('listWebhooks', () => {
  it('GETs /webhooks and returns unwrapped array', async () => {
    mockFetch.mockResolvedValueOnce(ok({ webhooks: [] }));
    const res = await listWebhooks(cfg);
    expect(lastCall().url).toBe('http://localhost:39999/webhooks');
    expect(Array.isArray(res)).toBe(true);
  });
});

describe('deleteWebhook', () => {
  it('DELETEs /webhooks/:id', async () => {
    mockFetch.mockResolvedValueOnce(ok({ deleted: true }));
    await deleteWebhook(cfg, 'wh_1');
    const { url, method } = lastCall();
    expect(method).toBe('DELETE');
    expect(url).toBe('http://localhost:39999/webhooks/wh_1');
  });
});

/* ── createKey ───────────────────────────────────────────── */

describe('createKey', () => {
  it('POSTs to /me/keys with name and valid_for_seconds', async () => {
    mockFetch.mockResolvedValueOnce(ok({ id: 'key_1', name: 'ci', key: 'sirr_key_abc', valid_after: 0, valid_before: 86400 }, 201));
    const res = await createKey(cfg, { name: 'ci', valid_for_seconds: 86400 });
    const { url, method, body } = lastCall();
    expect(method).toBe('POST');
    expect(url).toBe('http://localhost:39999/me/keys');
    expect(body).toEqual({ name: 'ci', valid_for_seconds: 86400 });
    expect(res.key).toBe('sirr_key_abc');
  });

  it('POSTs with valid_before', async () => {
    mockFetch.mockResolvedValueOnce(ok({ id: 'key_2', name: 'k', key: 'sirr_key_xyz', valid_after: 0, valid_before: 9999999 }, 201));
    await createKey(cfg, { name: 'k', valid_before: 9999999 });
    expect(lastCall().body).toEqual({ name: 'k', valid_before: 9999999 });
  });

  it('always uses /me/keys regardless of config.org', async () => {
    mockFetch.mockResolvedValueOnce(ok({ id: 'k', name: 'n', key: 'sirr_key_1', valid_after: 0, valid_before: 1 }, 201));
    await createKey(orgCfg, { name: 'n' });
    expect(lastCall().url).toBe('http://localhost:39999/me/keys');
  });
});

/* ── deleteKey ───────────────────────────────────────────── */

describe('deleteKey', () => {
  it('DELETEs /me/keys/:keyId', async () => {
    mockFetch.mockResolvedValueOnce(ok({ deleted: true }));
    await deleteKey(cfg, 'key_abc');
    const { url, method } = lastCall();
    expect(method).toBe('DELETE');
    expect(url).toBe('http://localhost:39999/me/keys/key_abc');
  });
});

/* ── getMe ───────────────────────────────────────────────── */

describe('getMe', () => {
  it('GETs /me with auth', async () => {
    const me = { id: 'p1', name: 'alice', role: 'writer', org_id: 'o1', metadata: {}, created_at: 0, keys: [] };
    mockFetch.mockResolvedValueOnce(ok(me));
    const res = await getMe(cfg);
    expect(lastCall().url).toBe('http://localhost:39999/me');
    expect(res.keys).toEqual([]);
  });
});

/* ── patchMe ─────────────────────────────────────────────── */

describe('patchMe', () => {
  it('PATCHes /me with metadata', async () => {
    mockFetch.mockResolvedValueOnce(ok({ updated: true }));
    const res = await patchMe(cfg, { team: 'platform' });
    const { url, method, body } = lastCall();
    expect(method).toBe('PATCH');
    expect(url).toBe('http://localhost:39999/me');
    expect(body).toEqual({ metadata: { team: 'platform' } });
    expect(res.updated).toBe(true);
  });
});

/* ── createOrg ───────────────────────────────────────────── */

describe('createOrg', () => {
  it('POSTs to /orgs', async () => {
    mockFetch.mockResolvedValueOnce(ok({ id: 'org_1', name: 'acme', created_at: 0 }, 201));
    const res = await createOrg(cfg, { name: 'acme' });
    const { url, method, body } = lastCall();
    expect(method).toBe('POST');
    expect(url).toBe('http://localhost:39999/orgs');
    expect(body).toEqual({ name: 'acme' });
    expect(res.id).toBe('org_1');
  });
});

describe('listOrgs', () => {
  it('GETs /orgs and returns unwrapped array', async () => {
    mockFetch.mockResolvedValueOnce(ok({ orgs: [] }));
    const res = await listOrgs(cfg);
    expect(lastCall().url).toBe('http://localhost:39999/orgs');
    expect(Array.isArray(res)).toBe(true);
  });
});

describe('deleteOrg', () => {
  it('DELETEs /orgs/:orgId', async () => {
    mockFetch.mockResolvedValueOnce(ok({ deleted: true }));
    await deleteOrg(cfg, 'org_1');
    const { url, method } = lastCall();
    expect(method).toBe('DELETE');
    expect(url).toBe('http://localhost:39999/orgs/org_1');
  });
});

/* ── createPrincipal ─────────────────────────────────────── */

describe('createPrincipal', () => {
  it('POSTs to /orgs/:orgId/principals', async () => {
    const p = { id: 'p1', name: 'alice', role: 'writer', org_id: 'org_1', metadata: {}, created_at: 0 };
    mockFetch.mockResolvedValueOnce(ok(p, 201));
    const res = await createPrincipal(cfg, 'org_1', { name: 'alice', role: 'writer' });
    const { url, method, body } = lastCall();
    expect(method).toBe('POST');
    expect(url).toBe('http://localhost:39999/orgs/org_1/principals');
    expect(body).toEqual({ name: 'alice', role: 'writer' });
    expect(res.id).toBe('p1');
  });
});

describe('listPrincipals', () => {
  it('GETs /orgs/:orgId/principals and returns unwrapped array', async () => {
    mockFetch.mockResolvedValueOnce(ok({ principals: [] }));
    const res = await listPrincipals(cfg, 'org_1');
    expect(lastCall().url).toBe('http://localhost:39999/orgs/org_1/principals');
    expect(Array.isArray(res)).toBe(true);
  });
});

describe('deletePrincipal', () => {
  it('DELETEs /orgs/:orgId/principals/:id', async () => {
    mockFetch.mockResolvedValueOnce(ok({ deleted: true }));
    await deletePrincipal(cfg, 'org_1', 'p_1');
    const { url, method } = lastCall();
    expect(method).toBe('DELETE');
    expect(url).toBe('http://localhost:39999/orgs/org_1/principals/p_1');
  });
});

/* ── createRole ──────────────────────────────────────────── */

describe('createRole', () => {
  it('POSTs to /orgs/:orgId/roles with name and permissions', async () => {
    const role = { name: 'auditor', permissions: 'rRlL', built_in: false, org_id: 'org_1', created_at: 0 };
    mockFetch.mockResolvedValueOnce(ok(role, 201));
    const res = await createRole(cfg, 'org_1', { name: 'auditor', permissions: 'rRlL' });
    const { url, method, body } = lastCall();
    expect(method).toBe('POST');
    expect(url).toBe('http://localhost:39999/orgs/org_1/roles');
    expect(body).toEqual({ name: 'auditor', permissions: 'rRlL' });
    expect(res.permissions).toBe('rRlL');
  });
});

describe('listRoles', () => {
  it('GETs /orgs/:orgId/roles and returns unwrapped array', async () => {
    mockFetch.mockResolvedValueOnce(ok({ roles: [] }));
    const res = await listRoles(cfg, 'org_1');
    expect(lastCall().url).toBe('http://localhost:39999/orgs/org_1/roles');
    expect(Array.isArray(res)).toBe(true);
  });
});

describe('deleteRole', () => {
  it('DELETEs /orgs/:orgId/roles/:name', async () => {
    mockFetch.mockResolvedValueOnce(ok({ deleted: true }));
    await deleteRole(cfg, 'org_1', 'auditor');
    const { url, method } = lastCall();
    expect(method).toBe('DELETE');
    expect(url).toBe('http://localhost:39999/orgs/org_1/roles/auditor');
  });
});

/* ── Error handling ──────────────────────────────────────── */

describe('error handling', () => {
  it('throws with status code in message', async () => {
    mockFetch.mockResolvedValueOnce(fail(403, { error: 'forbidden' }));
    await expect(listSecrets(cfg)).rejects.toThrow('403');
  });

  it('falls back to statusText for non-JSON error bodies', async () => {
    mockFetch.mockResolvedValueOnce(failText(429, 'Too Many Requests'));
    await expect(listSecrets(cfg)).rejects.toThrow('429');
  });

  it('includes error message from body', async () => {
    mockFetch.mockResolvedValueOnce(fail(402, { error: 'license required' }));
    await expect(pushSecret(cfg, { key: 'K', value: 'v' })).rejects.toThrow('license required');
  });
});
