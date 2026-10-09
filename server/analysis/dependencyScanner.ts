import fs from 'fs';
import path from 'path';
import { DependencyItem, DependencyVulnerability, Finding, Severity } from '../types.js';

interface RawDep {
  name: string;
  version: string;
  ecosystem: 'npm' | 'pypi' | 'go' | 'maven' | 'cargo' | 'other';
  manifestPath: string;
}

export class DependencyScanner {
  /**
   * Discovers manifests and parses dependencies without running any package manager scripts.
   * Uses OSV batch API to query all packages concurrently in a single rapid request.
   */
  public static async scanDependencies(
    scanId: string,
    repoDir: string,
    relativeFiles: string[]
  ): Promise<{ dependencies: DependencyItem[]; findings: Finding[] }> {
    const rawDeps: RawDep[] = [];

    for (const rel of relativeFiles) {
      const lower = rel.toLowerCase();
      const fullPath = path.join(repoDir, rel);

      try {
        if (lower.endsWith('package.json') && !lower.includes('node_modules')) {
          this.parsePackageJson(fullPath, rel, rawDeps);
        } else if (lower.endsWith('requirements.txt')) {
          this.parseRequirementsTxt(fullPath, rel, rawDeps);
        } else if (lower.endsWith('go.mod')) {
          this.parseGoMod(fullPath, rel, rawDeps);
        } else if (lower.endsWith('cargo.toml')) {
          this.parseCargoToml(fullPath, rel, rawDeps);
        }
      } catch (err) {
        // Continue parsing remaining files safely
      }
    }

    const dependencies: DependencyItem[] = [];
    const findings: Finding[] = [];

    const targetDeps = rawDeps.slice(0, 50);
    if (targetDeps.length === 0) {
      return { dependencies, findings };
    }

    // Batch query OSV API
    const vulnsMap = await this.queryOsvBatch(targetDeps);

    for (const dep of targetDeps) {
      const depKey = `${dep.name}@${dep.version}`;
      const vulnerabilities = vulnsMap.get(depKey) || [];

      const depItem: DependencyItem = {
        name: dep.name,
        version: dep.version,
        ecosystem: dep.ecosystem,
        manifestPath: dep.manifestPath,
        isDirect: true,
        vulnerabilities,
      };

      dependencies.push(depItem);

      for (const vuln of vulnerabilities) {
        findings.push({
          id: `dep-${scanId}-${findings.length + 1}`,
          scanId,
          title: `Vulnerable Dependency: ${dep.name}@${dep.version} (${vuln.cve || vuln.id})`,
          category: 'dependency',
          severity: vuln.severity,
          confidence: 'HIGH',
          filePath: dep.manifestPath,
          scannerName: 'SecretShield-OSV-Adapter',
          ruleId: vuln.id,
          cweId: 'CWE-1395: Dependency on Vulnerable Third-Party Component',
          owasp: 'A06:2021-Vulnerable and Outdated Components',
          evidence: `${vuln.summary || 'Known security vulnerability reported in upstream component advisory.'} Affected version: ${dep.version}${vuln.fixedVersion ? `, fixed in ${vuln.fixedVersion}` : ''}.`,
          maskedSnippet: `"${dep.name}": "${dep.version}"`,
          remediation: vuln.fixedVersion
            ? `Upgrade dependency ${dep.name} to version ${vuln.fixedVersion} or later in ${dep.manifestPath}.`
            : `Review advisory ${vuln.id} and test alternative package version or mitigation.`,
          status: 'OPEN',
          exposureType: 'CURRENT',
          firstSeenAt: new Date().toISOString(),
          lastSeenAt: new Date().toISOString(),
          tags: ['dependency', dep.ecosystem, vuln.cve || vuln.id],
          referenceUrls: [vuln.advisoryUrl],
        });
      }
    }

    return { dependencies, findings };
  }

  private static parsePackageJson(fullPath: string, rel: string, list: RawDep[]) {
    const raw = fs.readFileSync(fullPath, 'utf-8');
    const pkg = JSON.parse(raw);
    const all = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
    for (const [name, verStr] of Object.entries(all)) {
      if (typeof verStr === 'string') {
        const cleanVer = verStr.replace(/^[\^~>=<]/, '').trim();
        list.push({
          name,
          version: cleanVer,
          ecosystem: 'npm',
          manifestPath: rel,
        });
      }
    }
  }

  private static parseRequirementsTxt(fullPath: string, rel: string, list: RawDep[]) {
    const lines = fs.readFileSync(fullPath, 'utf-8').split('\n');
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('-')) continue;
      const match = trimmed.match(/^([a-zA-Z0-9_\-\.]+)(?:==|>=|<=|~=)([a-zA-Z0-9_\-\.]+)/);
      if (match) {
        list.push({
          name: match[1],
          version: match[2],
          ecosystem: 'pypi',
          manifestPath: rel,
        });
      }
    }
  }

  private static parseGoMod(fullPath: string, rel: string, list: RawDep[]) {
    const lines = fs.readFileSync(fullPath, 'utf-8').split('\n');
    let inRequire = false;
    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed.startsWith('require (')) {
        inRequire = true;
        continue;
      }
      if (inRequire && trimmed === ')') {
        inRequire = false;
        continue;
      }
      if (inRequire || trimmed.startsWith('require ')) {
        const clean = trimmed.replace(/^require\s+/, '');
        const parts = clean.split(/\s+/);
        if (parts.length >= 2) {
          list.push({
            name: parts[0],
            version: parts[1].replace(/^v/, ''),
            ecosystem: 'go',
            manifestPath: rel,
          });
        }
      }
    }
  }

  private static parseCargoToml(fullPath: string, rel: string, list: RawDep[]) {
    const lines = fs.readFileSync(fullPath, 'utf-8').split('\n');
    let inDeps = false;
    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed === '[dependencies]' || trimmed === '[dev-dependencies]') {
        inDeps = true;
        continue;
      }
      if (inDeps && trimmed.startsWith('[')) {
        inDeps = false;
        continue;
      }
      if (inDeps) {
        const match = trimmed.match(/^([a-zA-Z0-9_\-]+)\s*=\s*["']([^"']+)["']/);
        if (match) {
          list.push({
            name: match[1],
            version: match[2].replace(/^[\^~]/, ''),
            ecosystem: 'cargo',
            manifestPath: rel,
          });
        }
      }
    }
  }

  /**
   * Fast batch query to OSV open vulnerability database (resolves in ~200ms)
   */
  private static async queryOsvBatch(deps: RawDep[]): Promise<Map<string, DependencyVulnerability[]>> {
    const ecoMap: Record<string, string> = {
      npm: 'npm',
      pypi: 'PyPI',
      go: 'Go',
      cargo: 'crates.io',
      maven: 'Maven',
    };

    const resultsMap = new Map<string, DependencyVulnerability[]>();
    const queries = deps.map((d) => ({
      package: {
        name: d.name,
        ecosystem: ecoMap[d.ecosystem] || 'npm',
      },
      version: d.version,
    }));

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 4000);

    try {
      const resp = await fetch('https://api.osv.dev/v1/querybatch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ queries }),
        signal: controller.signal,
      });

      clearTimeout(timeout);
      if (!resp.ok) return resultsMap;

      const data = (await resp.json()) as { results?: Array<{ vulns?: any[] }> };
      if (!data.results || !Array.isArray(data.results)) return resultsMap;

      data.results.forEach((res, index) => {
        const dep = deps[index];
        if (!dep) return;
        const depKey = `${dep.name}@${dep.version}`;

        if (res.vulns && Array.isArray(res.vulns)) {
          const vulnsList: DependencyVulnerability[] = res.vulns.slice(0, 3).map((v) => {
            const cve = v.aliases?.find((a: string) => a.startsWith('CVE-'));
            const fixed = v.affected?.[0]?.ranges?.[0]?.events?.find((e: any) => e.fixed)?.fixed;

            let severity: Severity = 'MEDIUM';
            const sevStr = (v.database_specific?.severity || v.severity?.[0]?.type || '').toLowerCase();
            if (sevStr.includes('crit') || (v.cvss && v.cvss >= 9.0)) severity = 'CRITICAL';
            else if (sevStr.includes('high') || (v.cvss && v.cvss >= 7.0)) severity = 'HIGH';
            else if (sevStr.includes('low')) severity = 'LOW';

            return {
              id: v.id,
              cve,
              summary: v.summary || v.details?.slice(0, 150) || 'Known security vulnerability in package version',
              severity,
              fixedVersion: fixed,
              advisoryUrl: `https://osv.dev/vulnerability/${v.id}`,
            };
          });

          resultsMap.set(depKey, vulnsList);
        }
      });
    } catch {
      clearTimeout(timeout);
    }

    return resultsMap;
  }
}
