import { createHash, X509Certificate } from 'node:crypto';
import { normalizeHex } from './common';
import type { PeerCertificateSummary, ProbePeerCertificate } from './types';

export function isNonEmptyObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && Object.keys(value).length > 0;
}

export function hasPeerCertificate(value: unknown): value is ProbePeerCertificate {
  return isNonEmptyObject(value);
}

export function summarizePeerCertificate(
  cert: ProbePeerCertificate,
  depth: number,
): PeerCertificateSummary {
  const raw = Buffer.isBuffer(cert.raw) ? cert.raw : null;
  const x509 = raw ? new X509Certificate(raw) : null;
  const subject = x509?.subject ?? null;
  const issuer = x509?.issuer ?? null;

  return {
    depth,
    subject,
    issuer,
    subjectAltName: x509?.subjectAltName ?? cert.subjectaltname ?? null,
    serialNumber: x509?.serialNumber ?? cert.serialNumber ?? null,
    validFrom: x509?.validFrom ?? cert.valid_from ?? null,
    validTo: x509?.validTo ?? cert.valid_to ?? null,
    fingerprint256: x509?.fingerprint256 ?? cert.fingerprint256 ?? null,
    fingerprint512: x509?.fingerprint512 ?? cert.fingerprint512 ?? null,
    rawLength: raw?.length ?? null,
    isCA: x509?.ca ?? cert.ca ?? null,
    selfIssued: subject && issuer ? subject === issuer : null,
  };
}

export function buildPeerCertificateChain(
  peerCertificate: ProbePeerCertificate | null,
): PeerCertificateSummary[] {
  if (!peerCertificate) {
    return [];
  }

  const chain: PeerCertificateSummary[] = [];
  const seen = new Set<string>();
  let current: ProbePeerCertificate | null = peerCertificate;
  let depth = 0;

  while (current && hasPeerCertificate(current)) {
    const summary = summarizePeerCertificate(current, depth);
    const dedupeKey =
      summary.fingerprint256 ??
      `${summary.subject ?? 'unknown-subject'}:${summary.serialNumber ?? 'unknown-serial'}:${depth}`;
    if (seen.has(dedupeKey)) {
      break;
    }

    seen.add(dedupeKey);
    chain.push(summary);

    if (!('issuerCertificate' in current)) {
      break;
    }

    const issuerCertificate: ProbePeerCertificate | null = current.issuerCertificate;
    if (
      !issuerCertificate ||
      issuerCertificate === current ||
      !hasPeerCertificate(issuerCertificate)
    ) {
      break;
    }

    current = issuerCertificate;
    depth += 1;
  }

  return chain;
}

export function parseDerCertificate(der: Buffer): {
  subject?: string;
  issuer?: string;
  serialNumber?: string;
  validFrom?: string;
  validTo?: string;
  sha256: string;
  length: number;
} {
  const sha256 = createHash('sha256').update(der).digest('hex').toUpperCase();

  try {
    const cert = new X509Certificate(der);
    return {
      subject: cert.subject || undefined,
      issuer: cert.issuer || undefined,
      serialNumber: cert.serialNumber || undefined,
      validFrom: cert.validFrom || undefined,
      validTo: cert.validTo || undefined,
      sha256,
      length: der.length,
    };
  } catch {
    return { sha256, length: der.length };
  }
}

export function parseCertificateChain(hexPayload: string): Array<{
  sha256: string;
  length: number;
}> {
  const buffer = Buffer.from(normalizeHex(hexPayload), 'hex');
  const certs: Array<{ sha256: string; length: number }> = [];

  let cursor = 0;
  while (cursor < buffer.length - 4) {
    if (buffer[cursor] === 0x30) {
      const certData = buffer.subarray(cursor);
      const info = parseDerCertificate(certData);
      certs.push({ sha256: info.sha256, length: info.length });
      cursor += info.length;
    } else {
      cursor += 1;
    }
  }

  if (certs.length === 0 && buffer.length > 0) {
    certs.push({
      sha256: createHash('sha256').update(buffer).digest('hex').toUpperCase(),
      length: buffer.length,
    });
  }

  return certs;
}
