import { URL } from 'url';

export interface ValidationResult {
  isValid: boolean;
  normalizedUrl?: string;
  error?: string;
  provider?: 'GitHub' | 'GitLab' | 'Forgejo' | 'Gitea' | 'Bitbucket' | 'Generic Git';
  repoName?: string;
  owner?: string;
  warning?: string;
}

// Private IP and link-local ranges for SSRF protection
const FORBIDDEN_HOSTNAMES = new Set([
  'localhost',
  '127.0.0.1',
  '0.0.0.0',
  '::1',
  'metadata.google.internal',
  '169.254.169.254', // AWS/GCP/Azure link-local metadata
  'instance-data',
]);

function isPrivateIp(hostname: string): boolean {
  if (FORBIDDEN_HOSTNAMES.has(hostname.toLowerCase())) {
    return true;
  }

  // Check IPv4 ranges
  const ipv4Match = hostname.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ipv4Match) {
    const [, a, b] = ipv4Match.map(Number);
    // 127.0.0.0/8 (Loopback)
    if (a === 127) return true;
    // 10.0.0.0/8 (Private)
    if (a === 10) return true;
    // 172.16.0.0/12 (Private)
    if (a === 172 && b >= 16 && b <= 31) return true;
    // 192.168.0.0/16 (Private)
    if (a === 192 && b === 168) return true;
    // 169.254.0.0/16 (Link-local)
    if (a === 169 && b === 254) return true;
    // 0.0.0.0/8
    if (a === 0) return true;
  }

  // Check IPv6 loopback and link-local
  if (hostname.startsWith('[') && hostname.endsWith(']')) {
    const inner = hostname.slice(1, -1).toLowerCase();
    if (inner === '::1' || inner.startsWith('fe80:') || inner.startsWith('fc00:')) {
      return true;
    }
  }

  return false;
}

export function detectGitProvider(urlObj: URL): 'GitHub' | 'GitLab' | 'Forgejo' | 'Gitea' | 'Bitbucket' | 'Generic Git' {
  const host = urlObj.hostname.toLowerCase();
  if (host === 'github.com' || host.endsWith('.github.com')) return 'GitHub';
  if (host === 'gitlab.com' || host.endsWith('.gitlab.com')) return 'GitLab';
  if (host === 'bitbucket.org' || host.endsWith('.bitbucket.org')) return 'Bitbucket';
  if (host.includes('codeberg.org') || host.includes('forgejo')) return 'Forgejo';
  if (host.includes('gitea')) return 'Gitea';
  return 'Generic Git';
}

export function validateRepositoryUrl(rawUrl: string): ValidationResult {
  if (!rawUrl || typeof rawUrl !== 'string') {
    return { isValid: false, error: 'Repository URL is required.' };
  }

  const trimmed = rawUrl.trim();

  // Guard against command / flag injection
  if (trimmed.startsWith('-') || trimmed.includes('--upload-pack') || trimmed.includes('--config')) {
    return { isValid: false, error: 'Suspicious characters or flags detected in URL.' };
  }

  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    return { isValid: false, error: 'Invalid URL format. Please provide a valid HTTP/HTTPS Git URL.' };
  }

  // 1. Protocol validation: Only https (and http)
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    return {
      isValid: false,
      error: `Protocol '${parsed.protocol}' is prohibited. Only HTTPS Git repository URLs are accepted.`,
    };
  }

  // 2. Reject embedded credentials (user:pass@)
  if (parsed.username || parsed.password) {
    return {
      isValid: false,
      error: 'Embedded credentials (username/password in URL) are prohibited for security reasons.',
    };
  }

  // 3. SSRF checks
  const hostname = parsed.hostname;
  if (isPrivateIp(hostname)) {
    return {
      isValid: false,
      error: `Access to private network or link-local address '${hostname}' is blocked to prevent SSRF.`,
    };
  }

  // 4. Validate path structure
  const pathParts = parsed.pathname.replace(/^\/|\/$/g, '').split('/');
  if (pathParts.length < 2 || !pathParts[0] || !pathParts[1]) {
    return {
      isValid: false,
      error: 'URL path must specify both an owner/organization and repository name (e.g., https://github.com/org/repo).',
    };
  }

  const owner = pathParts[0];
  let repoName = pathParts[1].replace(/\.git$/, '');

  // Strip trailing slashes and normalize
  const normalizedUrl = `${parsed.protocol}//${parsed.hostname}${parsed.port ? ':' + parsed.port : ''}/${owner}/${repoName}.git`;
  const provider = detectGitProvider(parsed);

  let warning: string | undefined;
  if (parsed.protocol === 'http:') {
    warning = 'Repository URL uses unencrypted HTTP. HTTPS is recommended.';
  }

  return {
    isValid: true,
    normalizedUrl,
    provider,
    repoName,
    owner,
    warning,
  };
}
