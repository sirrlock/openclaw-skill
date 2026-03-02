/**
 * Integration tests for @sirrlock/openclaw-skill.
 *
 * Starts a real sirrd process, exercises every function against it,
 * and cleans up all created resources in finally-blocks.
 *
 * Run with:
 *   SIRR_EXTERNAL=1 npm run test:integration
 *
 * Or against an existing server:
 *   SIRR_EXTERNAL=1 SIRR_SERVER=http://localhost:39999 SIRR_API_KEY=<key> npm run test:integration
 */

import { type ChildProcess, spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from '@jest/globals';
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

const RUN = !!process.env['SIRR_EXTERNAL'];
const maybeDescribe = RUN ? describe : describe.skip;

/* ── Server setup ────────────────────────────────────────── */

const PORT = 39996;
const MASTER_KEY = 'openclaw-integration-test-key';
const LICENSE_KEY = 'sirr_lic_0000000000000000000000000000000000000000';

let sirrd: ChildProcess | undefined;
let dataDir: string | undefined;

let masterCfg: SirrConfig;
let orgId: string;
let bootstrapKey: string; // auto-init principal key (admin role)

async function waitForHealth(retries = 40): Promise<void> {
  for (let i = 0; i < retries; i++) {
    try {
      const r = await fetch(`http://localhost:${PORT}/health`);
      if (r.ok) return;
    } catch { /* not ready yet */ }
    await new Promise(r => setTimeout(r, 200));
  }
  throw new Error('sirrd did not become healthy in time');
}

beforeAll(async () => {
  const externalServer = process.env['SIRR_SERVER'];
  const externalKey    = process.env['SIRR_API_KEY'];

  if (externalServer && externalKey) {
    // Use an already-running server
    masterCfg = { serverUrl: externalServer, token: externalKey };
    await waitForHealth();
    return;
  }

  dataDir = mkdtempSync(join(tmpdir(), 'sirr-e2e-openclaw-'));

  sirrd = spawn('sirrd', ['serve', '--port', String(PORT)], {
    env: {
      ...process.env,
      SIRR_API_KEY: MASTER_KEY,
      SIRR_LICENSE_KEY: LICENSE_KEY,
      SIRR_AUTOINIT: '1',
      SIRR_DATA_DIR: dataDir,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  const logChunks: Buffer[] = [];
  sirrd.stderr?.on('data', (c: Buffer) => logChunks.push(c));
  sirrd.stdout?.on('data', (c: Buffer) => logChunks.push(c));

  await waitForHealth();
  await new Promise(r => setTimeout(r, 300)); // let autoinit flush

  const log = Buffer.concat(logChunks).toString('utf8');
  const orgMatch = log.match(/org_id:\s+([0-9a-f]{32})/);
  const keyMatch = log.match(/key=(sirr_key_[0-9a-f]+)/);
  if (!orgMatch || !keyMatch) throw new Error(`Failed to parse autoinit output:\n${log}`);

  orgId       = orgMatch[1];
  bootstrapKey = keyMatch[1];
  masterCfg   = { serverUrl: `http://localhost:${PORT}`, token: MASTER_KEY };
}, 20_000);

afterAll(async () => {
  sirrd?.kill();
  if (dataDir) rmSync(dataDir, { recursive: true, force: true });
});

/* ── 1. Health check ─────────────────────────────────────── */

maybeDescribe('health', () => {
  it('GET /health returns ok', async () => {
    const res = await healthCheck(masterCfg);
    expect(res.status).toBe('ok');
  });
});

/* ── 2. Public bucket — push / get / delete ──────────────── */

maybeDescribe('public bucket round-trip', () => {
  it('push → get → delete', async () => {
    await pushSecret(masterCfg, { key: 'INTEGRATION_KEY', value: 'integration-value' });
    try {
      const got = await getSecret(masterCfg, 'INTEGRATION_KEY');
      expect(got?.value).toBe('integration-value');
    } finally {
      await deleteSecret(masterCfg, 'INTEGRATION_KEY');
    }
    const gone = await getSecret(masterCfg, 'INTEGRATION_KEY');
    expect(gone).toBeNull();
  });

  it('getSecret returns null for missing key', async () => {
    const res = await getSecret(masterCfg, 'definitely-does-not-exist');
    expect(res).toBeNull();
  });

  it('listSecrets includes pushed keys', async () => {
    await pushSecret(masterCfg, { key: 'LIST_TEST', value: 'v' });
    try {
      const secrets = await listSecrets(masterCfg);
      expect(secrets.some(s => s.key === 'LIST_TEST')).toBe(true);
    } finally {
      await deleteSecret(masterCfg, 'LIST_TEST');
    }
  });
});

/* ── 3. sealOnExpiry + patch ─────────────────────────────── */

maybeDescribe('sealable secret + patch', () => {
  it('push with delete:false → patch TTL → still readable', async () => {
    await pushSecret(masterCfg, {
      key: 'SEALABLE',
      value: 'original',
      max_reads: 2,
      delete: false,
    });
    try {
      await patchSecret(masterCfg, 'SEALABLE', { ttl_seconds: 3600 });
      const got = await getSecret(masterCfg, 'SEALABLE');
      expect(got?.value).toBe('original');
    } finally {
      await deleteSecret(masterCfg, 'SEALABLE');
    }
  });
});

/* ── 4. Burn-after-read ──────────────────────────────────── */

maybeDescribe('burn-after-read', () => {
  it('second read returns null', async () => {
    await pushSecret(masterCfg, { key: 'BURN_ME', value: 'secret', max_reads: 1 });
    const first = await getSecret(masterCfg, 'BURN_ME');
    expect(first?.value).toBe('secret');
    const second = await getSecret(masterCfg, 'BURN_ME');
    expect(second).toBeNull();
  });
});

/* ── 5. checkSecret (HEAD) ───────────────────────────────── */

maybeDescribe('checkSecret', () => {
  it('returns null for missing secret', async () => {
    const res = await checkSecret(masterCfg, 'definitely-does-not-exist');
    expect(res).toBeNull();
  });

  it('does not consume a read — count unchanged after HEAD', async () => {
    await pushSecret(masterCfg, { key: 'HEAD_TEST', value: 'v', max_reads: 1 });
    try {
      const status = await checkSecret(masterCfg, 'HEAD_TEST');
      expect(status?.status).toBe('active');
      expect(status?.reads_remaining).toBe(1); // not consumed by HEAD
      // Now actually read it (increments counter, burns the secret)
      const got = await getSecret(masterCfg, 'HEAD_TEST');
      expect(got?.value).toBe('v');
      // Burned — should be gone
      const gone = await getSecret(masterCfg, 'HEAD_TEST');
      expect(gone).toBeNull();
    } finally {
      await deleteSecret(masterCfg, 'HEAD_TEST').catch(() => { /* already burned */ });
    }
  });
});

/* ── 6. Audit log ────────────────────────────────────────── */

maybeDescribe('audit', () => {
  it('returns events after pushing and reading', async () => {
    await pushSecret(masterCfg, { key: 'AUDIT_TARGET', value: 'v' });
    try {
      await getSecret(masterCfg, 'AUDIT_TARGET');
      const events = await queryAudit(masterCfg, { limit: 20 });
      expect(Array.isArray(events)).toBe(true);
    } finally {
      await deleteSecret(masterCfg, 'AUDIT_TARGET');
    }
  });
});

/* ── 7. Prune ────────────────────────────────────────────── */

maybeDescribe('pruneSecrets', () => {
  it('returns pruned count', async () => {
    const res = await pruneSecrets(masterCfg);
    expect(typeof res.pruned).toBe('number');
  });
});

/* ── 8. Webhooks ─────────────────────────────────────────── */

maybeDescribe('webhooks', () => {
  it('create → list → delete', async () => {
    const { id, secret } = await createWebhook(masterCfg, { url: 'https://example.com/hook' });
    expect(typeof secret).toBe('string');
    try {
      const webhooks = await listWebhooks(masterCfg);
      expect(webhooks.some(w => w.id === id)).toBe(true);
    } finally {
      await deleteWebhook(masterCfg, id);
    }
    const after = await listWebhooks(masterCfg);
    expect(after.some(w => w.id === id)).toBe(false);
  });
});

/* ── 9. Org lifecycle ────────────────────────────────────── */

maybeDescribe('org lifecycle', () => {
  it('create → list → delete', async () => {
    const org = await createOrg(masterCfg, { name: 'test-org' });
    expect(org.id).toBeTruthy();
    try {
      const orgs = await listOrgs(masterCfg);
      expect(orgs.some(o => o.id === org.id)).toBe(true);
    } finally {
      await deleteOrg(masterCfg, org.id);
    }
    const after = await listOrgs(masterCfg);
    expect(after.some(o => o.id === org.id)).toBe(false);
  });
});

/* ── 10. Principal lifecycle ─────────────────────────────── */

maybeDescribe('principal lifecycle', () => {
  it('create → list → delete within the autoinit org', async () => {
    // autoinit creates orgId for us; masterCfg can manage it
    const principal = await createPrincipal(masterCfg, orgId, { name: 'ci-bot', role: 'writer' });
    expect(principal.id).toBeTruthy();
    try {
      const principals = await listPrincipals(masterCfg, orgId);
      expect(principals.some(p => p.id === principal.id)).toBe(true);
    } finally {
      await deletePrincipal(masterCfg, orgId, principal.id);
    }
    const after = await listPrincipals(masterCfg, orgId);
    expect(after.some(p => p.id === principal.id)).toBe(false);
  });
});

/* ── 11. Role lifecycle ──────────────────────────────────── */

maybeDescribe('role lifecycle', () => {
  it('create → list → delete custom role', async () => {
    await createRole(masterCfg, orgId, { name: 'auditor-e2e', permissions: 'rRlL' });
    try {
      const roles = await listRoles(masterCfg, orgId);
      expect(roles.some(r => r.name === 'auditor-e2e')).toBe(true);
    } finally {
      await deleteRole(masterCfg, orgId, 'auditor-e2e');
    }
    const after = await listRoles(masterCfg, orgId);
    expect(after.some(r => r.name === 'auditor-e2e')).toBe(false);
  });
});

/* ── 12. Me + Keys ───────────────────────────────────────── */

maybeDescribe('me and keys', () => {
  it('getMe returns principal with keys array', async () => {
    const principalCfg: SirrConfig = {
      serverUrl: masterCfg.serverUrl,
      token: bootstrapKey,
      org: orgId,
    };
    const me = await getMe(principalCfg);
    expect(me.org_id).toBe(orgId);
    expect(Array.isArray(me.keys)).toBe(true);
  });

  it('patchMe updates metadata', async () => {
    const principalCfg: SirrConfig = {
      serverUrl: masterCfg.serverUrl,
      token: bootstrapKey,
      org: orgId,
    };
    const res = await patchMe(principalCfg, { env: 'ci' });
    expect(res.updated).toBe(true);
  });

  it('createKey → visible in getMe → deleteKey', async () => {
    const principalCfg: SirrConfig = {
      serverUrl: masterCfg.serverUrl,
      token: bootstrapKey,
      org: orgId,
    };
    const created = await createKey(principalCfg, { name: 'e2e-temp-key', valid_for_seconds: 300 });
    expect(created.key).toMatch(/^sirr_key_/);
    try {
      const me = await getMe(principalCfg);
      expect(me.keys.some(k => k.id === created.id)).toBe(true);
    } finally {
      await deleteKey(principalCfg, created.id);
    }
    const after = await getMe(principalCfg);
    expect(after.keys.some(k => k.id === created.id)).toBe(false);
  });
});

/* ── 13. Org-scoped secrets ──────────────────────────────── */

maybeDescribe('org-scoped secrets', () => {
  it('push → get → delete in org scope', async () => {
    const principalCfg: SirrConfig = {
      serverUrl: masterCfg.serverUrl,
      token: bootstrapKey,
      org: orgId,
    };
    await pushSecret(principalCfg, { key: 'ORG_SECRET', value: 'org-value' });
    try {
      const got = await getSecret(principalCfg, 'ORG_SECRET');
      expect(got?.value).toBe('org-value');
    } finally {
      await deleteSecret(principalCfg, 'ORG_SECRET');
    }
    const gone = await getSecret(principalCfg, 'ORG_SECRET');
    expect(gone).toBeNull();
  });
});
