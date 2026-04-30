import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import { objectTool } from './support';

export const fridaTools: Tool[] = [
  objectTool(
    'tls_cert_pin_bypass_frida',
    'Bypass certificate pinning via Frida injection (supports BoringSSL, Chrome, OkHttp).',
  ),
];
