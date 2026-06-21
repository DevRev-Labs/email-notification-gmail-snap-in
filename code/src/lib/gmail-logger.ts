/**
 * Structured logging for the Gmail email snap-in.
 * Never pass secrets, tokens, or raw keyring payloads into these methods.
 */

import type { LogLevelName } from '../config/log-level';
import { resolveLogLevel, shouldEmitLogLevel } from '../config/log-level';

const DEFAULT_NAMESPACE = '[gmail-email]';

const SENSITIVE_KEY_PATTERN =
  /(secret|password|token|authorization|refresh_token|access_token|client_secret|api[_-]?key|keyring)/i;
const REDACTED = '[REDACTED]';

function redact(value: unknown, depth = 0): unknown {
  if (depth > 4 || value === null || value === undefined) {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item) => redact(item, depth + 1));
  }
  if (typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [key, raw] of Object.entries(value as Record<string, unknown>)) {
      out[key] = SENSITIVE_KEY_PATTERN.test(key) ? REDACTED : redact(raw, depth + 1);
    }
    return out;
  }
  return value;
}

export class GmailSnapInLogger {
  public constructor(private readonly namespace: string) {}

  public error(...args: unknown[]): void {
    this.emit('error', console.error, args);
  }

  public warn(...args: unknown[]): void {
    this.emit('warn', console.warn, args);
  }

  public info(...args: unknown[]): void {
    this.emit('info', console.log, args);
  }

  public debug(...args: unknown[]): void {
    this.emit('debug', console.log, args);
  }

  private emit(level: LogLevelName, sink: (...a: unknown[]) => void, payload: unknown[]): void {
    const minimum = resolveLogLevel();
    if (!shouldEmitLogLevel(minimum, level)) {
      return;
    }
    const safe = payload.map((arg) => redact(arg));
    sink(this.namespace, ...safe);
  }
}

export function createGmailLogger(namespace: string = DEFAULT_NAMESPACE): GmailSnapInLogger {
  return new GmailSnapInLogger(namespace);
}
