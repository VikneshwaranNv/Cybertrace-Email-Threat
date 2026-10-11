import { Request, Response, NextFunction } from 'express';
import { AuthSession, UserRole } from './types';
import { authService } from './authService';
import { auditLogger } from './auditLogger';

export interface AuthenticatedRequest extends Request {
  user?: AuthSession;
}

export function extractBearerToken(req: Request): string | null {
  const authHeader = req.headers.authorization || req.headers['authorization'];
  if (typeof authHeader === 'string') {
    const match = authHeader.match(/^bearer\s+(.+)$/i);
    if (match && match[1]) {
      return match[1].trim();
    }
  }

  const customHeader = req.headers['x-auth-token'];
  if (typeof customHeader === 'string' && customHeader.trim()) {
    return customHeader.trim();
  }

  return null;
}

/**
 * Server-Side Authentication Guard
 * Validates cryptographic session token before granting access to forensic APIs
 */
export function authenticateUser(req: AuthenticatedRequest, res: Response, next: NextFunction) {
  const token = extractBearerToken(req);

  if (!token) {
    auditLogger.record({
      action: 'AUTH_FAILURE',
      status: 'DENIED',
      ip: req.ip || req.socket.remoteAddress,
      resourceId: req.path,
      resourceType: 'API_ENDPOINT',
      details: `Unauthenticated request blocked on ${req.method} ${req.path}`,
    });

    return res.status(401).json({
      error: 'Unauthorized: Valid authentication token required',
      code: 'AUTH_TOKEN_REQUIRED',
    });
  }

  const session = authService.validateToken(token);
  if (!session) {
    auditLogger.record({
      action: 'AUTH_FAILURE',
      status: 'DENIED',
      ip: req.ip || req.socket.remoteAddress,
      resourceId: req.path,
      resourceType: 'API_ENDPOINT',
      details: `Invalid or expired session token on ${req.method} ${req.path}`,
    });

    return res.status(401).json({
      error: 'Unauthorized: Session is invalid or has expired',
      code: 'AUTH_TOKEN_EXPIRED',
    });
  }

  req.user = session;
  next();
}

/**
 * Server-Side Role-Based Authorization Guard (RBAC)
 * Enforces ANALYST vs ADMIN functional permissions
 */
export function requireRole(...allowedRoles: UserRole[]) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(401).json({
        error: 'Unauthorized: Authentication required before authorization verification',
      });
    }

    if (!allowedRoles.includes(req.user.role)) {
      auditLogger.record({
        action: 'AUTHORIZATION_FAILURE',
        status: 'DENIED',
        actorId: req.user.userId,
        actorEmail: req.user.email,
        actorRole: req.user.role,
        ip: req.ip || req.socket.remoteAddress,
        resourceId: req.path,
        resourceType: 'PROTECTED_ENDPOINT',
        details: `Access denied: Role ${req.user.role} attempted action requiring [${allowedRoles.join(', ')}] on ${req.method} ${req.path}`,
      });

      return res.status(403).json({
        error: `Forbidden: Role '${req.user.role}' lacks permission for this operation. Required: [${allowedRoles.join(', ')}]`,
        code: 'INSUFFICIENT_ROLE_PERMISSIONS',
      });
    }

    next();
  };
}

/**
 * Optional authentication middleware for public endpoints that may adapt response if authenticated
 */
export function optionalAuthenticateUser(req: AuthenticatedRequest, res: Response, next: NextFunction) {
  const token = extractBearerToken(req);
  if (token) {
    const session = authService.validateToken(token);
    if (session) {
      req.user = session;
    }
  }
  next();
}
