import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import { objectTool, TLS_VERSION_VALUES } from './support';

export const tlsAnalysisTools: Tool[] = [
  objectTool('tls_keylog_enable', 'Enable SSLKEYLOGFILE output for BoringSSL-compatible clients.'),
  objectTool('tls_keylog_parse', 'Parse an SSLKEYLOGFILE and summarize available key material.', {
    path: {
      type: 'string',
      description: 'Path to SSLKEYLOGFILE (uses default if omitted)',
    },
  }),
  objectTool(
    'tls_keylog_disable',
    'Disable SSLKEYLOGFILE capture and unset the environment variable.',
    {
      path: {
        type: 'string',
        description: 'Specific path to disable (uses current path if omitted)',
      },
    },
  ),
  objectTool(
    'tls_decrypt_payload',
    'Decrypt a TLS payload using a provided key, nonce, and algorithm.',
    {
      encryptedHex: {
        type: 'string',
        description: 'Hex-encoded encrypted payload',
      },
      keyHex: {
        type: 'string',
        description: 'Hex-encoded decryption key',
      },
      nonceHex: {
        type: 'string',
        description: 'Hex-encoded nonce/IV',
      },
      algorithm: {
        type: 'string',
        description: 'Cipher algorithm (default: aes-256-gcm)',
        default: 'aes-256-gcm',
      },
      authTagHex: {
        type: 'string',
        description: 'Hex-encoded authentication tag (for AEAD ciphers)',
      },
    },
    ['encryptedHex', 'keyHex', 'nonceHex'],
  ),
  objectTool(
    'tls_keylog_summarize',
    'Summarize the contents of an SSLKEYLOGFILE by label distribution.',
    {
      content: {
        type: 'string',
        description: 'Inline keylog content to summarize (uses file if omitted)',
      },
    },
  ),
  objectTool(
    'tls_keylog_lookup_secret',
    'Look up a TLS secret by client random hex from the parsed keylog.',
    {
      clientRandom: {
        type: 'string',
        description: 'Hex-encoded client random',
      },
      label: {
        type: 'string',
        description: 'Optional label filter (e.g. CLIENT_RANDOM)',
      },
    },
    ['clientRandom'],
  ),
  objectTool(
    'tls_cert_pin_bypass',
    'Return a certificate pinning bypass strategy for the selected platform.',
    {
      target: {
        type: 'string',
        enum: ['android', 'ios', 'desktop'],
        description: 'Target platform for bypass strategy',
      },
    },
    ['target'],
  ),
  objectTool(
    'tls_parse_handshake',
    'Parse TLS record header and handshake metadata (version, cipher suites, SNI, extensions) from raw hex. Optionally decrypts payload preview when keylog is available.',
    {
      rawHex: {
        type: 'string',
        description: 'Hex-encoded TLS handshake record',
      },
      decrypt: {
        type: 'boolean',
        description: 'If true, attempt payload decryption using loaded keylog (default: false)',
      },
    },
    ['rawHex'],
  ),
  objectTool('tls_cipher_suites', 'List IANA TLS cipher suites, optionally filtered by keyword.', {
    filter: {
      type: 'string',
      description: 'Keyword filter for cipher suite names',
    },
  }),
  objectTool(
    'tls_parse_certificate',
    'Parse a TLS Certificate message from raw hex and extract fingerprints.',
    {
      rawHex: {
        type: 'string',
        description: 'Hex-encoded certificate data',
      },
    },
    ['rawHex'],
  ),
  objectTool(
    'tls_probe_endpoint',
    'Connect to a TLS endpoint and report certificate chain basics, trust result, ALPN, protocol, cipher, and SNI/hostname validation details for authorized target testing.',
    {
      host: {
        type: 'string',
        description: 'Target host name or IP address',
      },
      port: {
        type: 'number',
        default: 443,
        description: 'Target TLS port (default: 443)',
      },
      servername: {
        type: 'string',
        description: 'Optional SNI and hostname validation override',
      },
      alpnProtocols: {
        type: 'array',
        items: { type: 'string' },
        description: 'Optional ALPN protocols to offer, in preference order',
      },
      timeoutMs: {
        type: 'number',
        default: 5000,
        description: 'Probe timeout in milliseconds',
      },
      minVersion: {
        type: 'string',
        enum: [...TLS_VERSION_VALUES],
        description: 'Optional minimum TLS version',
      },
      maxVersion: {
        type: 'string',
        enum: [...TLS_VERSION_VALUES],
        description: 'Optional maximum TLS version',
      },
      caPem: {
        type: 'string',
        description: 'Optional PEM-encoded CA bundle used for trust evaluation',
      },
      caPath: {
        type: 'string',
        description: 'Optional path to a PEM-encoded CA bundle used for trust evaluation',
      },
      allowInvalidCertificates: {
        type: 'boolean',
        default: false,
        description: 'Allow untrusted certificate chains while still reporting the failure',
      },
      skipHostnameCheck: {
        type: 'boolean',
        default: false,
        description: 'Skip hostname verification while still reporting the requested target',
      },
    },
    ['host'],
  ),
];
