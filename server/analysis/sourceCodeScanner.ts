import fs from 'fs';
import path from 'path';
import { Finding, Severity } from '../types.js';

interface SastRule {
  id: string;
  title: string;
  severity: Severity;
  category: 'sast' | 'auth_security' | 'privacy';
  languages: string[]; // extensions: '.js', '.ts', '.py', '.go', '.java', '.php'
  pattern: RegExp;
  cwe: string;
  owasp: string;
  evidenceDesc: string;
  remediation: string;
}

const SAST_RULES: SastRule[] = [
  {
    id: 'SAST-SQLI-RAW',
    title: 'SQL Injection: Dynamic Query String Concatenation',
    severity: 'CRITICAL',
    category: 'sast',
    languages: ['.js', '.ts', '.py', '.php', '.java', '.go'],
    pattern: /(?:SELECT|INSERT|UPDATE|DELETE|DROP)\s+.*?(?:WHERE|SET|FROM)\s+.*?(?:\+|%s|\${|f["']).*?(?:req\.|params|body|request\.|input|user_input)/i,
    cwe: 'CWE-89: Improper Neutralization of Special Elements used in an SQL Command',
    owasp: 'A03:2021-Injection',
    evidenceDesc: 'SQL query constructed via dynamic string formatting with untrusted user input.',
    remediation: 'Use parameterized queries or prepared statements (e.g. `$1`, `?`, or ORM query builders like Prisma, SQLAlchemy, Sequelize). Never concatenate untrusted strings directly into SQL statements.',
  },
  {
    id: 'SAST-CMD-INJECTION',
    title: 'Command Injection: Unsanitized Subprocess Execution',
    severity: 'CRITICAL',
    category: 'sast',
    languages: ['.js', '.ts', '.py', '.php'],
    pattern: /(?:exec|execSync|spawn|os\.system|subprocess\.Popen|subprocess\.call|shell_exec|system)\s*\(\s*(?:`|f['"]|['"].*?\+|.*?req\.|.*?request\.)/i,
    cwe: 'CWE-78: Improper Neutralization of Special Elements used in an OS Command',
    owasp: 'A03:2021-Injection',
    evidenceDesc: 'Execution of system shell command using dynamic input without argument array separation.',
    remediation: 'Avoid invoking the shell (`shell=False` in Python). Pass commands as an array of pre-validated arguments, or use safe domain-specific libraries instead of shell utilities.',
  },
  {
    id: 'SAST-XSS-UNESCAPED',
    title: 'Cross-Site Scripting (XSS): Direct HTML Injection',
    severity: 'HIGH',
    category: 'sast',
    languages: ['.js', '.ts', '.jsx', '.tsx', '.php'],
    pattern: /(?:dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:|\.innerHTML\s*=\s*|document\.write\s*\()\s*.*?(?:req\.|props\.|state\.|user|input|param)/i,
    cwe: 'CWE-79: Improper Neutralization of Input During Web Page Generation',
    owasp: 'A03:2021-Injection',
    evidenceDesc: 'Untrusted user data rendered directly into DOM without HTML escaping or sanitization.',
    remediation: 'Sanitize HTML with DOMPurify before injection, or use safe template bindings (e.g., standard React JSX text nodes, textContent) that automatically escape HTML entities.',
  },
  {
    id: 'SAST-PATH-TRAVERSAL',
    title: 'Path Traversal: Unsanitized File Access',
    severity: 'HIGH',
    category: 'sast',
    languages: ['.js', '.ts', '.py', '.php', '.go'],
    pattern: /(?:fs\.readFile|fs\.readFileSync|open|sendFile|send_file|file_get_contents)\s*\(\s*(?:path\.join|os\.path\.join)?\s*\(?.*?(?:req\.|request\.|query\.|params\.)/i,
    cwe: 'CWE-22: Improper Limitation of a Pathname to a Restricted Directory',
    owasp: 'A01:2021-Broken Access Control',
    evidenceDesc: 'Filesystem operation directly accesses file path derived from client-supplied request parameters.',
    remediation: 'Validate paths using a strict whitelist or resolve paths with `path.resolve` and verify that the target starts with the canonical root directory (`resolved.startsWith(BASE_DIR)`).',
  },
  {
    id: 'SAST-SSRF-UNVALIDATED',
    title: 'Server-Side Request Forgery (SSRF): Unchecked Egress Request',
    severity: 'HIGH',
    category: 'sast',
    languages: ['.js', '.ts', '.py', '.go'],
    pattern: /(?:axios\.get|axios\.post|fetch|requests\.get|requests\.post|urllib\.request\.urlopen|http\.Get)\s*\(\s*(?:req\.|request\.|params\.|body\.url|query\.url)/i,
    cwe: 'CWE-918: Server-Side Request Forgery (SSRF)',
    owasp: 'A10:2021-Server-Side Request Forgery',
    evidenceDesc: 'Outbound network HTTP client makes request to user-controllable destination URL.',
    remediation: 'Implement an egress allowlist of approved domains. Block requests to RFC 1918 private IP ranges, link-local metadata endpoints (169.254.169.254), and loopback interfaces.',
  },
  {
    id: 'SAST-DESERIALIZATION-UNSAFE',
    title: 'Insecure Deserialization: Arbitrary Code Execution Risk',
    severity: 'CRITICAL',
    category: 'sast',
    languages: ['.py', '.js', '.php'],
    pattern: /(?:pickle\.loads|pickle\.load|_pickle\.loads|yaml\.load\s*\([^,)]+\)|unserialize\s*\()/i,
    cwe: 'CWE-502: Deserialization of Untrusted Data',
    owasp: 'A08:2021-Software and Data Integrity Failures',
    evidenceDesc: 'Untrusted input passed to unsafe deserialization routine capable of instantiating arbitrary objects or executing code.',
    remediation: 'Use safe serializers like JSON or Protocol Buffers. In Python, use `yaml.safe_load()` instead of `yaml.load()`. Never deserialize untrusted Python pickle or PHP serialize data.',
  },
  {
    id: 'SAST-WEAK-CRYPTO-HASH',
    title: 'Weak Cryptographic Hash Algorithm (MD5/SHA1)',
    severity: 'MEDIUM',
    category: 'sast',
    languages: ['.js', '.ts', '.py', '.go', '.java', '.php'],
    pattern: /(?:createHash\s*\(\s*['"](?:md5|sha1)['"]|hashlib\.(?:md5|sha1)\s*\(|md5\s*\(|sha1\s*\()/i,
    cwe: 'CWE-328: Use of Weak Hash',
    owasp: 'A02:2021-Cryptographic Failures',
    evidenceDesc: 'MD5 or SHA-1 hash algorithm used in code. These algorithms suffer from known collision attacks.',
    remediation: 'Upgrade to SHA-256, SHA-384, or SHA-512 for data integrity. For password hashing, use dedicated slow KDF algorithms such as Argon2id, bcrypt, or scrypt.',
  },
  {
    id: 'SAST-WEAK-CIPHER-ECB',
    title: 'Insecure Cipher Mode (ECB Mode / Weak Algorithm)',
    severity: 'HIGH',
    category: 'sast',
    languages: ['.js', '.ts', '.py', '.java', '.go'],
    pattern: /(?:aes-[0-9]{3}-ecb|MODE_ECB|DES|Blowfish|RC4)/i,
    cwe: 'CWE-327: Use of a Broken or Risky Cryptographic Algorithm',
    owasp: 'A02:2021-Cryptographic Failures',
    evidenceDesc: 'Electronic Codebook (ECB) mode or obsolete cipher detected. ECB leaks plaintext patterns.',
    remediation: 'Use authenticated encryption modes such as AES-256-GCM or ChaCha20-Poly1305 with uniquely generated nonces/IVs for every encryption operation.',
  },
  {
    id: 'SAST-INSECURE-RANDOM',
    title: 'Cryptographically Weak Pseudorandom Number Generator',
    severity: 'LOW',
    category: 'sast',
    languages: ['.js', '.ts', '.py', '.php'],
    pattern: /(?:Math\.random\s*\(\)|random\.random\s*\(\)|rand\s*\(\)|mt_rand\s*\()/i,
    cwe: 'CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator',
    owasp: 'A02:2021-Cryptographic Failures',
    evidenceDesc: 'Standard PRNG used. If used for security tokens, passwords, or session IDs, values are predictable.',
    remediation: 'Use `crypto.randomBytes()` or `crypto.getRandomValues()` in JavaScript/TypeScript, and `secrets` module in Python for security-sensitive tokens.',
  },
  {
    id: 'SAST-CORS-WILDCARD-CREDS',
    title: 'Permissive CORS: Wildcard Origin with Credentials Allowed',
    severity: 'MEDIUM',
    category: 'sast',
    languages: ['.js', '.ts', '.py', '.go'],
    pattern: /(?:origin\s*:\s*['"]\*['"].*?credentials\s*:\s*true|Access-Control-Allow-Origin['"]?\s*,\s*['"]\*['"].*?Allow-Credentials)/is,
    cwe: 'CWE-942: Permissive Cross-domain Policy with Untrusted Domains',
    owasp: 'A01:2021-Broken Access Control',
    evidenceDesc: 'CORS policy enables credential sharing with wildcard origin, exposing sensitive user sessions.',
    remediation: 'Explicitly specify trusted origin domains instead of using `*`. Do not enable `credentials: true` alongside wildcard origins.',
  },
  {
    id: 'SAST-DANGEROUS-EVAL',
    title: 'Arbitrary Code Execution via Dynamic eval() / Function()',
    severity: 'CRITICAL',
    category: 'sast',
    languages: ['.js', '.ts', '.py', '.php'],
    pattern: /(?:eval\s*\(\s*(?!['"][^'"]*['"]\s*\))|new\s+Function\s*\()/i,
    cwe: 'CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code',
    owasp: 'A03:2021-Injection',
    evidenceDesc: 'Dynamic eval() or Function constructor called with non-constant input.',
    remediation: 'Eliminate eval(). Use safe data parsing (JSON.parse) or domain-specific parsers without dynamic code execution.',
  },
  {
    id: 'SAST-PROTOTYPE-POLLUTION',
    title: 'Potential Prototype Pollution Vulnerability',
    severity: 'HIGH',
    category: 'sast',
    languages: ['.js', '.ts'],
    pattern: /(?:__proto__|constructor\s*\[\s*['"]prototype['"]\s*\])/i,
    cwe: 'CWE-1321: Improperly Controlled Modification of Object Prototype Attributes',
    owasp: 'A03:2021-Injection',
    evidenceDesc: 'Direct access or assignment to __proto__ or constructor.prototype property.',
    remediation: 'Filter or reject keys named __proto__, constructor, and prototype during object merges or use Object.create(null).',
  },
  {
    id: 'SAST-STACK-TRACE-LEAK',
    title: 'Sensitive Information Disclosure via Stack Trace / Debug Error',
    severity: 'LOW',
    category: 'sast',
    languages: ['.js', '.ts', '.py'],
    pattern: /(?:res\.(?:send|json)\s*\(\s*.*?err\.stack|traceback\.print_exc\s*\()/i,
    cwe: 'CWE-209: Generation of Error Message Containing Sensitive Information',
    owasp: 'A05:2021-Security Misconfiguration',
    evidenceDesc: 'Internal stack trace or debugging error details sent directly in HTTP response.',
    remediation: 'Log full stack traces internally to secure logger, and return sanitized generic error messages to clients.',
  },
];

export class SourceCodeScanner {
  public static scanFiles(scanId: string, repoDir: string, relativeFiles: string[]): Finding[] {
    const findings: Finding[] = [];

    for (const relPath of relativeFiles) {
      const ext = path.extname(relPath).toLowerCase();
      const applicableRules = SAST_RULES.filter((r) => r.languages.includes(ext));
      if (applicableRules.length === 0) continue;

      const fullPath = path.join(repoDir, relPath);
      let content = '';
      try {
        const stats = fs.statSync(fullPath);
        if (stats.size > 500 * 1024) continue; // Skip files > 500KB
        content = fs.readFileSync(fullPath, 'utf-8');
      } catch {
        continue;
      }

      const lines = content.split('\n');

      for (const rule of applicableRules) {
        if (!rule.pattern.test(content)) continue;

        // Locate exact line number without infinite regex loop
        let matchLineNumber = 1;
        let matchedSnippet = '';

        for (let i = 0; i < lines.length; i++) {
          const l = lines[i];
          if (l.length < 400 && rule.pattern.test(l)) {
            matchLineNumber = i + 1;
            matchedSnippet = l.trim();
            break;
          }
        }

        if (!matchedSnippet && lines.length > 0) {
          matchedSnippet = lines[0].trim();
        }

        findings.push({
          id: `sast-${scanId}-${findings.length + 1}`,
          scanId,
          title: rule.title,
          category: rule.category,
          severity: rule.severity,
          confidence: 'HIGH',
          filePath: relPath,
          lineNumber: matchLineNumber,
          scannerName: 'SecretShield-Semgrep-Adapter',
          ruleId: rule.id,
          cweId: rule.cwe,
          owasp: rule.owasp,
          evidence: `${rule.evidenceDesc} (Matched pattern in file ${relPath})`,
          maskedSnippet: matchedSnippet.slice(0, 160),
          remediation: rule.remediation,
          status: 'OPEN',
          exposureType: 'CURRENT',
          firstSeenAt: new Date().toISOString(),
          lastSeenAt: new Date().toISOString(),
          tags: ['sast', 'code-security', rule.id],
          referenceUrls: [
            `https://cwe.mitre.org/data/definitions/${rule.cwe.match(/CWE-(\d+)/)?.[1] || '79'}.html`,
            'https://owasp.org/Top10/',
          ],
        });
      }
    }

    return findings;
  }
}
