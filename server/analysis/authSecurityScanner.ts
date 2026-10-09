import fs from 'fs';
import path from 'path';
import { Finding, Severity } from '../types.js';

interface AuthRule {
  id: string;
  title: string;
  severity: Severity;
  pattern: RegExp;
  cwe: string;
  evidence: string;
  remediation: string;
}

const AUTH_RULES: AuthRule[] = [
  {
    id: 'AUTH-PLAINTEXT-PASSWORD-CHECK',
    title: 'Plaintext Password Comparison Detected',
    severity: 'HIGH',
    pattern: /(?:user\.password|account\.password|stored_password|db_pass)\s*===?\s*(?:req\.body\.password|password|input_password|params\.password)/i,
    cwe: 'CWE-256: Plaintext Storage of a Password',
    evidence: 'Direct equality comparison between stored user password and submitted password indicates passwords are not hashed with a slow cryptographic algorithm.',
    remediation: 'Never compare passwords in plaintext. Store salted password hashes using bcrypt, Argon2id, or PBKDF2, and verify using timing-safe comparison functions (e.g. `bcrypt.compare`).',
  },
  {
    id: 'AUTH-JWT-NONE-ALGORITHM',
    title: 'Insecure JWT: Algorithm "none" or Unverified Signature',
    severity: 'CRITICAL',
    pattern: /(?:jwt\.verify\s*\([^,)]+,\s*['"]none['"]|algorithms\s*:\s*\[['"]none['"]\]|jwt\.decode\s*\([^,)]+\)\s*;\s*\/\/\s*trust)/i,
    cwe: 'CWE-347: Improper Verification of Cryptographic Signature',
    evidence: 'JWT verification permits "none" algorithm or relies on decode without cryptographic signature validation.',
    remediation: 'Explicitly enforce asymmetric (RS256/ES256) or symmetric (HS256) signature verification with a pinned algorithms whitelist. Disallow algorithm switching and "none".',
  },
  {
    id: 'AUTH-MISSING-TOKEN-EXPIRATION',
    title: 'JWT Generated Without Expiration Claim (exp)',
    severity: 'MEDIUM',
    pattern: /jwt\.sign\s*\(\s*(?:\{[^\}]+\}|[a-zA-Z0-9_]+)\s*,\s*(?:secret|[a-zA-Z0-9_]+)\s*(?:,\s*\{(?![^}]*expiresIn)[^}]*\})?\s*\)/,
    cwe: 'CWE-613: Insufficient Session Expiration',
    evidence: 'JWT token signed without specifying an `expiresIn` parameter or `exp` claim, creating permanent tokens.',
    remediation: 'Always include short-lived token expiration (e.g., `expiresIn: "15m"`) and implement refresh token rotation for extended sessions.',
  },
  {
    id: 'AUTH-INSECURE-COOKIE-FLAGS',
    title: 'Session Cookie Missing HttpOnly or Secure Flag',
    severity: 'MEDIUM',
    pattern: /(?:res\.cookie|set_cookie)\s*\(\s*['"][^'"]*(?:session|token|auth|sid)[^'"]*['"]\s*,\s*[^,)]+,\s*\{(?![^}]*(?:httpOnly\s*:\s*true|secure\s*:\s*true))[^}]*\}/i,
    cwe: 'CWE-1004: Sensitive Cookie Without HttpOnly Flag',
    evidence: 'Session or authentication cookie set without `httpOnly: true` or `secure: true` attributes, exposing session to client-side XSS theft.',
    remediation: 'Always set `httpOnly: true`, `secure: true`, and `sameSite: "lax"` (or "strict") when storing session identifiers or authentication tokens in cookies.',
  },
  {
    id: 'AUTH-MISSING-RBAC-CHECK',
    title: 'Potential Broken Object-Level Authorization (BOLA/IDOR)',
    severity: 'HIGH',
    pattern: /(?:app|router)\.(?:get|post|put|delete)\s*\(\s*['"]\/api\/(?:users|accounts|orders|documents)\/:id['"][^)]*function\s*\([^\)]*\)\s*\{(?![^}]*(?:req\.user\.id|hasPermission|authorize|role))/i,
    cwe: 'CWE-639: Authorization Bypass Through User-Controlled Key',
    evidence: 'Route handler fetches or modifies user records based on client-provided ID parameter without validating that the authenticated user owns or is authorized to access that record.',
    remediation: 'Enforce authorization checks against `req.user.id` or implement an access-control middleware (RBAC/ABAC) before executing database operations on user resources.',
  },
  {
    id: 'AUTH-PII-LOGGING',
    title: 'Sensitive Personal Information (PII / Passwords) in Logs',
    severity: 'LOW',
    pattern: /(?:console\.log|logger\.(?:info|debug|warn|error)|logging\.(?:info|debug))\s*\(\s*.*?(?:req\.body|password|credit_card|ssn|token|secret)/i,
    cwe: 'CWE-532: Insertion of Sensitive Information into Log File',
    evidence: 'Logging statement directly outputs request body, passwords, or authentication tokens.',
    remediation: 'Sanitize logs using redaction filters (e.g., Pino redacting sensitive keys) before writing to output streams.',
  },
];

export class AuthSecurityScanner {
  public static scanFiles(scanId: string, repoDir: string, relativeFiles: string[]): Finding[] {
    const findings: Finding[] = [];

    for (const relPath of relativeFiles) {
      const ext = path.extname(relPath).toLowerCase();
      if (!['.js', '.ts', '.py', '.php', '.go', '.java'].includes(ext)) continue;

      const fullPath = path.join(repoDir, relPath);
      let content = '';
      try {
        const stats = fs.statSync(fullPath);
        if (stats.size > 1024 * 1024) continue;
        content = fs.readFileSync(fullPath, 'utf-8');
      } catch {
        continue;
      }

      const lines = content.split('\n');

      for (const rule of AUTH_RULES) {
        rule.pattern.lastIndex = 0;
        const match = rule.pattern.exec(content);
        if (match) {
          const matchIndex = match.index;
          let lineNumber = 1;
          for (let i = 0; i < matchIndex; i++) {
            if (content[i] === '\n') lineNumber++;
          }

          const matchedSnippet = lines[lineNumber - 1] || '';

          findings.push({
            id: `auth-${scanId}-${findings.length + 1}`,
            scanId,
            title: rule.title,
            category: 'auth_security',
            severity: rule.severity,
            confidence: 'MEDIUM',
            filePath: relPath,
            lineNumber,
            scannerName: 'SecretShield-Auth-Analyzer',
            ruleId: rule.id,
            cweId: rule.cwe,
            owasp: 'A07:2021-Identification and Authentication Failures',
            evidence: `${rule.evidence} (Static inspection signal, requires manual verification)`,
            maskedSnippet: matchedSnippet.trim().slice(0, 160),
            remediation: rule.remediation,
            status: 'OPEN',
            exposureType: 'CURRENT',
            firstSeenAt: new Date().toISOString(),
            lastSeenAt: new Date().toISOString(),
            tags: ['auth', 'user-security', rule.id],
            referenceUrls: [
              'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html',
              'https://cwe.mitre.org/data/definitions/287.html',
            ],
          });
        }
      }
    }

    return findings;
  }
}
