import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import { objectTool, TLS_VERSION_VALUES } from './support';

export const sessionTools: Tool[] = [
  objectTool(
    'tcp_open',
    'Open a stateful TCP session and return a sessionId for follow-up read/write calls.',
    {
      host: {
        type: 'string',
        default: '127.0.0.1',
        description: 'Target host name or IP address',
      },
      port: {
        type: 'number',
        description: 'Target TCP port (1-65535)',
      },
      timeoutMs: {
        type: 'number',
        default: 5000,
        description: 'Connection timeout in milliseconds',
      },
      noDelay: {
        type: 'boolean',
        default: true,
        description: 'Enable TCP_NODELAY on the socket after connect',
      },
    },
    ['port'],
  ),
  objectTool(
    'tcp_write',
    'Write raw bytes to an open TCP session; accepts hex or UTF-8 text input.',
    {
      sessionId: {
        type: 'string',
        description: 'Session id returned by tcp_open',
      },
      dataHex: {
        type: 'string',
        description: 'Hex-encoded payload to write',
      },
      dataText: {
        type: 'string',
        description: 'UTF-8 text payload to write (alternative to dataHex)',
      },
      timeoutMs: {
        type: 'number',
        default: 5000,
        description: 'Write timeout in milliseconds',
      },
    },
    ['sessionId'],
  ),
  objectTool(
    'tcp_read_until',
    'Read from an open TCP session until a delimiter is observed or a byte limit is reached.',
    {
      sessionId: {
        type: 'string',
        description: 'Session id returned by tcp_open',
      },
      delimiterHex: {
        type: 'string',
        description: 'Hex-encoded delimiter to stop at',
      },
      delimiterText: {
        type: 'string',
        description: 'UTF-8 delimiter to stop at (alternative to delimiterHex)',
      },
      includeDelimiter: {
        type: 'boolean',
        default: true,
        description: 'Include the delimiter bytes in the returned payload',
      },
      maxBytes: {
        type: 'number',
        description: 'Optional maximum number of bytes to return even if no delimiter matches',
      },
      timeoutMs: {
        type: 'number',
        default: 5000,
        description: 'Read timeout in milliseconds',
      },
    },
    ['sessionId'],
  ),
  objectTool(
    'tcp_close',
    'Close an open TCP session and release its buffered state.',
    {
      sessionId: {
        type: 'string',
        description: 'Session id returned by tcp_open',
      },
      force: {
        type: 'boolean',
        default: false,
        description: 'Destroy the socket immediately instead of sending FIN first',
      },
      timeoutMs: {
        type: 'number',
        default: 1000,
        description: 'Close wait timeout in milliseconds before forcing socket destruction',
      },
    },
    ['sessionId'],
  ),
  objectTool(
    'tls_open',
    'Open a stateful TLS session with explicit trust and hostname policy controls, then return a sessionId.',
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
        description: 'Connection timeout in milliseconds',
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
  objectTool(
    'tls_write',
    'Write raw bytes to an open TLS session; accepts hex or UTF-8 text input.',
    {
      sessionId: {
        type: 'string',
        description: 'Session id returned by tls_open',
      },
      dataHex: {
        type: 'string',
        description: 'Hex-encoded payload to write',
      },
      dataText: {
        type: 'string',
        description: 'UTF-8 text payload to write (alternative to dataHex)',
      },
      timeoutMs: {
        type: 'number',
        default: 5000,
        description: 'Write timeout in milliseconds',
      },
    },
    ['sessionId'],
  ),
  objectTool(
    'tls_read_until',
    'Read from an open TLS session until a delimiter is observed or a byte limit is reached.',
    {
      sessionId: {
        type: 'string',
        description: 'Session id returned by tls_open',
      },
      delimiterHex: {
        type: 'string',
        description: 'Hex-encoded delimiter to stop at',
      },
      delimiterText: {
        type: 'string',
        description: 'UTF-8 delimiter to stop at (alternative to delimiterHex)',
      },
      includeDelimiter: {
        type: 'boolean',
        default: true,
        description: 'Include the delimiter bytes in the returned payload',
      },
      maxBytes: {
        type: 'number',
        description: 'Optional maximum number of bytes to return even if no delimiter matches',
      },
      timeoutMs: {
        type: 'number',
        default: 5000,
        description: 'Read timeout in milliseconds',
      },
    },
    ['sessionId'],
  ),
  objectTool(
    'tls_close',
    'Close an open TLS session and release its buffered state.',
    {
      sessionId: {
        type: 'string',
        description: 'Session id returned by tls_open',
      },
      force: {
        type: 'boolean',
        default: false,
        description: 'Destroy the TLS socket immediately instead of sending close_notify/FIN first',
      },
      timeoutMs: {
        type: 'number',
        default: 1000,
        description: 'Close wait timeout in milliseconds before forcing socket destruction',
      },
    },
    ['sessionId'],
  ),
];
