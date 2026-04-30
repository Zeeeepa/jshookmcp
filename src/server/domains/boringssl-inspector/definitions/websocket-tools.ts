import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import { objectTool, TLS_VERSION_VALUES } from './support';

export const websocketTools: Tool[] = [
  objectTool(
    'websocket_open',
    'Open a stateful WebSocket session over ws or wss, perform the client handshake, and return a sessionId.',
    {
      url: {
        type: 'string',
        description: 'Full ws:// or wss:// URL (mutually exclusive with explicit host/path fields)',
      },
      scheme: {
        type: 'string',
        enum: ['ws', 'wss'],
        default: 'ws',
        description: 'WebSocket transport scheme when url is not provided',
      },
      host: {
        type: 'string',
        description: 'Target host name or IP address when url is not provided',
      },
      port: {
        type: 'number',
        description: 'Target port (defaults to 80 for ws, 443 for wss)',
      },
      path: {
        type: 'string',
        default: '/',
        description: 'Request path including optional query string when url is not provided',
      },
      subprotocols: {
        type: 'array',
        items: { type: 'string' },
        description: 'Optional Sec-WebSocket-Protocol values to offer',
      },
      timeoutMs: {
        type: 'number',
        default: 5000,
        description: 'Handshake timeout in milliseconds',
      },
      servername: {
        type: 'string',
        description: 'Optional SNI and hostname validation override for wss sessions',
      },
      alpnProtocols: {
        type: 'array',
        items: { type: 'string' },
        description: 'Optional ALPN protocols to offer for wss sessions',
      },
      minVersion: {
        type: 'string',
        enum: [...TLS_VERSION_VALUES],
        description: 'Optional minimum TLS version for wss sessions',
      },
      maxVersion: {
        type: 'string',
        enum: [...TLS_VERSION_VALUES],
        description: 'Optional maximum TLS version for wss sessions',
      },
      caPem: {
        type: 'string',
        description: 'Optional PEM-encoded CA bundle for wss trust evaluation',
      },
      caPath: {
        type: 'string',
        description: 'Optional path to a PEM-encoded CA bundle for wss trust evaluation',
      },
      allowInvalidCertificates: {
        type: 'boolean',
        default: false,
        description: 'Allow untrusted certificate chains for wss while still reporting the failure',
      },
      skipHostnameCheck: {
        type: 'boolean',
        default: false,
        description:
          'Skip hostname verification for wss while still reporting the requested target',
      },
    },
  ),
  objectTool(
    'websocket_send_frame',
    'Send a single WebSocket frame on an open session using a minimal opcode set (text, binary, ping, pong, close).',
    {
      sessionId: {
        type: 'string',
        description: 'Session id returned by websocket_open',
      },
      frameType: {
        type: 'string',
        enum: ['text', 'binary', 'ping', 'pong', 'close'],
        description: 'Outgoing frame opcode',
      },
      dataText: {
        type: 'string',
        description: 'UTF-8 payload for text/ping/pong/close frames',
      },
      dataHex: {
        type: 'string',
        description: 'Hex-encoded payload for binary/ping/pong/close frames',
      },
      closeCode: {
        type: 'number',
        description: 'Optional close status code when frameType is close',
      },
      closeReason: {
        type: 'string',
        description: 'Optional UTF-8 close reason when frameType is close',
      },
      timeoutMs: {
        type: 'number',
        default: 5000,
        description: 'Write timeout in milliseconds',
      },
    },
    ['sessionId', 'frameType'],
  ),
  objectTool(
    'websocket_read_frame',
    'Read the next queued WebSocket frame from an open session.',
    {
      sessionId: {
        type: 'string',
        description: 'Session id returned by websocket_open',
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
    'websocket_close',
    'Close an open WebSocket session and release its queued frame state.',
    {
      sessionId: {
        type: 'string',
        description: 'Session id returned by websocket_open',
      },
      force: {
        type: 'boolean',
        default: false,
        description:
          'Destroy the underlying socket immediately without sending a close frame first',
      },
      closeCode: {
        type: 'number',
        description: 'Optional close status code when force is false',
      },
      closeReason: {
        type: 'string',
        description: 'Optional UTF-8 close reason when force is false',
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
