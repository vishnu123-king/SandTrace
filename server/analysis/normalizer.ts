import { Finding, ScanSummary } from '../types.js';

export class FindingsNormalizer {
  /**
   * Normalizes and deduplicates findings across different scanner engines
   */
  public static normalizeAndDeduplicate(rawFindings: Finding[]): Finding[] {
    const deduped: Finding[] = [];
    const seenMap = new Map<string, Finding>();

    for (const f of rawFindings) {
      // Create deduplication key: category + path + (line or fingerprint or rule)
      const locKey = f.rawSecretFingerprint
        ? `sec:${f.rawSecretFingerprint}:${f.filePath}`
        : `${f.category}:${f.filePath}:${f.lineNumber || 0}:${f.ruleId}`;

      const existing = seenMap.get(locKey);
      if (existing) {
        // Merge references and scanners
        if (!existing.scannerName.includes(f.scannerName)) {
          existing.scannerName += `, ${f.scannerName}`;
        }
        if (f.referenceUrls && existing.referenceUrls) {
          existing.referenceUrls = Array.from(new Set([...existing.referenceUrls, ...f.referenceUrls]));
        }
        // Upgrade severity if duplicate has higher severity
        const sevOrder = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 };
        if (sevOrder[f.severity] > sevOrder[existing.severity]) {
          existing.severity = f.severity;
          existing.title = f.title;
        }
      } else {
        seenMap.set(locKey, { ...f });
      }
    }

    deduped.push(...seenMap.values());

    // Sort by severity (CRITICAL down to INFO) then category
    const sevOrder: Record<string, number> = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 };
    deduped.sort((a, b) => {
      const diff = (sevOrder[b.severity] || 0) - (sevOrder[a.severity] || 0);
      if (diff !== 0) return diff;
      return a.category.localeCompare(b.category);
    });

    return deduped;
  }

  public static generateSummary(findings: Finding[]): ScanSummary {
    const summary: ScanSummary = {
      total: findings.length,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
      secretsCount: 0,
      sastCount: 0,
      dependencyCount: 0,
      configCount: 0,
      authCount: 0,
      historicalCount: 0,
      currentCount: 0,
    };

    for (const f of findings) {
      switch (f.severity) {
        case 'CRITICAL':
          summary.critical++;
          break;
        case 'HIGH':
          summary.high++;
          break;
        case 'MEDIUM':
          summary.medium++;
          break;
        case 'LOW':
          summary.low++;
          break;
        case 'INFO':
          summary.info++;
          break;
      }

      switch (f.category) {
        case 'secret':
          summary.secretsCount++;
          break;
        case 'sast':
          summary.sastCount++;
          break;
        case 'dependency':
          summary.dependencyCount++;
          break;
        case 'configuration':
          summary.configCount++;
          break;
        case 'auth_security':
          summary.authCount++;
          break;
      }

      if (f.exposureType === 'HISTORICAL') {
        summary.historicalCount++;
      } else {
        summary.currentCount++;
      }
    }

    return summary;
  }
}
