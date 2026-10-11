export type UserRole = 'ANALYST' | 'ADMIN' | 'SENIOR_ANALYST' | 'AUDITOR';

export interface UserRecord {
  id: string;
  email: string;
  name: string;
  role: UserRole;
  passwordHash: string;
  salt: string;
  createdAt: string;
  lastLoginAt?: string;
  emailVerified?: boolean;
  verificationCode?: string;
  resetToken?: string;
  resetExpiresAt?: number;
}

export interface UserPublicProfile {
  id: string;
  email: string;
  name: string;
  role: UserRole;
  emailVerified?: boolean;
  badgeNumber?: string;
  organization?: string;
  createdAt?: string;
}

export interface AuthSession {
  token: string;
  userId: string;
  email: string;
  name: string;
  role: UserRole;
  createdAt: string;
  expiresAt: string;
  rememberMe?: boolean;
}

export type AuditAction =
  | 'LOGIN_SUCCESS'
  | 'LOGIN_FAILED'
  | 'LOGOUT'
  | 'PASSWORD_RESET_REQUESTED'
  | 'PASSWORD_RESET_COMPLETED'
  | 'EMAIL_VERIFIED'
  | 'CASE_CREATED'
  | 'CASE_ACCESSED'
  | 'CASE_STATUS_CHANGED'
  | 'CASE_PRIORITY_CHANGED'
  | 'CASE_ASSIGNMENT_CHANGED'
  | 'NOTE_ADDED'
  | 'REPORT_GENERATED'
  | 'COPILOT_QUERY'
  | 'LEDGER_VERIFIED'
  | 'LEDGER_TAMPER_SIMULATED'
  | 'LEDGER_RESEALED'
  | 'AUTHORIZATION_FAILURE'
  | 'AUTH_FAILURE'
  | 'USER_CREATED'
  | 'PASSWORD_RESET_BLOCKED'
  | 'BULK_TRIAGE_DEMO_LOADED'
  | 'BULK_TRIAGE_INGESTION_STARTED'
  | 'BULK_ITEM_PROMOTED_TO_CASE';

export interface AuditLogEntry {
  id: string;
  timestamp: string;
  action: AuditAction;
  actorId?: string;
  actorEmail?: string;
  actorRole?: UserRole | 'ANONYMOUS';
  ip?: string;
  resourceId?: string;
  resourceType?: string;
  status: 'SUCCESS' | 'DENIED' | 'FAILURE';
  details: string;
}
