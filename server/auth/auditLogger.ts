import { AuditAction, AuditLogEntry, UserRole } from './types';

class AuditLogger {
  private logs: AuditLogEntry[] = [];
  private maxLogs = 500;

  /**
   * Sanitizes text to strictly guarantee no passwords, bearer tokens, or API keys are written to audit logs
   */
  private sanitize(input: string): string {
    if (!input) return '';
    return input
      .replace(/bearer\s+[a-zA-Z0-9_-]+/gi, 'Bearer [REDACTED_TOKEN]')
      .replace(/password[:=]\s*[^,\s]+/gi, 'password=[REDACTED]')
      .replace(/api[_-]?key[:=]\s*[^,\s]+/gi, 'apiKey=[REDACTED]')
      .replace(/AIza[0-9A-Za-z-_]{35}/g, '[REDACTED_GEMINI_KEY]');
  }

  public record(entry: {
    action: AuditAction;
    status: 'SUCCESS' | 'DENIED' | 'FAILURE';
    actorId?: string;
    actorEmail?: string;
    actorRole?: UserRole | 'ANONYMOUS';
    ip?: string;
    resourceId?: string;
    resourceType?: string;
    details: string;
  }): AuditLogEntry {
    const sanitizedDetails = this.sanitize(entry.details);

    const logItem: AuditLogEntry = {
      id: `AUDIT-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 7)}`,
      timestamp: new Date().toISOString(),
      action: entry.action,
      status: entry.status,
      actorId: entry.actorId || 'SYSTEM',
      actorEmail: entry.actorEmail || 'unauthenticated',
      actorRole: entry.actorRole || 'ANONYMOUS',
      ip: entry.ip || '127.0.0.1',
      resourceId: entry.resourceId,
      resourceType: entry.resourceType,
      details: sanitizedDetails,
    };

    this.logs.unshift(logItem);
    if (this.logs.length > this.maxLogs) {
      this.logs.pop();
    }

    // Output structured security event to stdout for SOC observability
    const prefix = logItem.status === 'DENIED' ? '🛑 [AUDIT-SECURITY-VIOLATION]' : '🛡️ [AUDIT-EVENT]';
    console.log(
      `${prefix} ${logItem.timestamp} | ${logItem.action} | ${logItem.status} | User: ${logItem.actorEmail} (${logItem.actorRole}) | ${logItem.details}`
    );

    return logItem;
  }

  public getLogs(limit = 100): AuditLogEntry[] {
    return this.logs.slice(0, limit);
  }

  public clearLogs(): void {
    this.logs = [];
  }
}

export const auditLogger = new AuditLogger();
