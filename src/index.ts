/**
 * @sirrlock/openclaw-skill
 *
 * OpenClaw workspace skill wrapping the simplified Sirr REST API via the Node.js SDK.
 */

// @ts-ignore
import { SirrClient, SirrClientOptions, SecretResponse, SecretStatus, AuditResponse, SecretMetadata } from "@sirrlock/node";

/* ── Secrets ─────────────────────────────────────────────────── */

/** Create a secret. Returns metadata including the hash. */
export async function pushSecret(
  config: SirrClientOptions,
  params: {
    value: string;
    ttl_seconds?: number;
    reads?: number;
    prefix?: string;
  },
): Promise<SecretResponse> {
  const client = new SirrClient(config);
  const { value, ...opts } = params;
  return client.push(value, opts);
}

/** Read a secret's value. Consumes a read.
 *  Returns null if 410 (burned/expired/non-existent). */
export async function getSecret(
  config: SirrClientOptions,
  hash: string,
): Promise<string | null> {
  const client = new SirrClient(config);
  return client.get(hash);
}

/** Metadata only via HEAD. Does NOT consume a read.
 *  Returns null if 410 (burned/expired/non-existent). */
export async function inspectSecret(
  config: SirrClientOptions,
  hash: string,
): Promise<SecretStatus | null> {
  const client = new SirrClient(config);
  return client.inspect(hash);
}

/** Update a secret's value/TTL/reads (owner key required). */
export async function patchSecret(
  config: SirrClientOptions,
  hash: string,
  params: {
    value?: string;
    ttl_seconds?: number;
    reads?: number;
  },
): Promise<SecretResponse> {
  const client = new SirrClient(config);
  return client.patch(hash, params);
}

/** Burn a secret immediately (DELETE). */
export async function burnSecret(
  config: SirrClientOptions,
  hash: string,
): Promise<void> {
  const client = new SirrClient(config);
  await client.burn(hash);
}

/** Get the audit trail for a secret (owner key required). */
export async function auditSecret(
  config: SirrClientOptions,
  hash: string,
): Promise<AuditResponse> {
  const client = new SirrClient(config);
  return client.audit(hash);
}

/** List all secrets owned by the calling key. */
export async function listSecrets(config: SirrClientOptions): Promise<SecretMetadata[]> {
  const client = new SirrClient(config);
  return client.list();
}

/** Check whether the Sirr server is reachable. No auth required. */
export async function healthCheck(config: SirrClientOptions): Promise<{ status: string }> {
  const client = new SirrClient(config);
  return client.health();
}
