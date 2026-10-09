import { ScanSummary } from '../types.js';

export interface RiskEvaluation {
  score: number;
  rating: 'CRITICAL' | 'HIGH' | 'ELEVATED' | 'MODERATE' | 'LOW';
  headline: string;
  postureAssessment: string;
  keyRiskDrivers: string[];
}

export class RiskScorer {
  public static calculate(summary: ScanSummary): RiskEvaluation {
    if (summary.total === 0) {
      return {
        score: 0,
        rating: 'LOW',
        headline: 'Clean Baseline — Zero Automated Findings Detected',
        postureAssessment: 'No known secrets, high-severity CVEs, or static code vulnerabilities detected by automated scanner rules. Note: this baseline does not prove an application is completely secure; manual review and penetration testing are recommended.',
        keyRiskDrivers: ['No critical vulnerabilities found in configured ruleset'],
      };
    }

    // Weighted risk accumulation
    let rawScore = 0;
    rawScore += summary.critical * 28;
    rawScore += summary.high * 14;
    rawScore += summary.medium * 5;
    rawScore += summary.low * 1;

    // Bonus weight for active live exposed secrets or historical credential leakage
    if (summary.secretsCount > 0) {
      rawScore += 10;
    }
    if (summary.historicalCount > 0) {
      rawScore += 5;
    }

    // Clamp score to 100 max, 1 min
    const score = Math.min(100, Math.max(5, rawScore));

    let rating: 'CRITICAL' | 'HIGH' | 'ELEVATED' | 'MODERATE' | 'LOW';
    if (score >= 80) rating = 'CRITICAL';
    else if (score >= 60) rating = 'HIGH';
    else if (score >= 40) rating = 'ELEVATED';
    else if (score >= 20) rating = 'MODERATE';
    else rating = 'LOW';

    const keyDrivers: string[] = [];
    if (summary.critical > 0) {
      keyDrivers.push(`${summary.critical} Critical Severity issues identified (immediate exploitation hazard)`);
    }
    if (summary.secretsCount > 0) {
      keyDrivers.push(`${summary.secretsCount} Hardcoded Secrets / Tokens requiring credential revocation`);
    }
    if (summary.dependencyCount > 0) {
      keyDrivers.push(`${summary.dependencyCount} Known Vulnerable Components / CVEs in dependency manifests`);
    }
    if (summary.historicalCount > 0) {
      keyDrivers.push(`${summary.historicalCount} Credentials retained in Git commit history`);
    }
    if (summary.sastCount > 0) {
      keyDrivers.push(`${summary.sastCount} Source Code Vulnerabilities (injection/control-flow risks)`);
    }

    let headline = '';
    let postureAssessment = '';

    switch (rating) {
      case 'CRITICAL':
        headline = 'Severe Risk — Immediate Exploitation Hazard';
        postureAssessment = 'The repository contains active critical vulnerabilities or exposed authentication keys that could lead to immediate unauthorized infrastructure or database access.';
        break;
      case 'HIGH':
        headline = 'Elevated Risk — High Priority Remediation Required';
        postureAssessment = 'Multiple high-severity vulnerabilities or insecure architectural patterns were detected. Immediate remediation is strongly recommended before production release.';
        break;
      case 'ELEVATED':
        headline = 'Moderate Risk — Security Deficiencies Present';
        postureAssessment = 'Several vulnerabilities or configuration misalignments were detected that weaken the security posture of the application.';
        break;
      case 'MODERATE':
        headline = 'Controlled Risk — Minor Security Recommendations';
        postureAssessment = 'The repository exhibits generally sound controls with limited medium-to-low severity findings that should be addressed during regular maintenance cycles.';
        break;
      case 'LOW':
        headline = 'Low Risk Posture';
        postureAssessment = 'Few low-priority or informational findings detected. Security hygiene is relatively high based on automated checks.';
        break;
    }

    return {
      score,
      rating,
      headline,
      postureAssessment,
      keyRiskDrivers: keyDrivers.length > 0 ? keyDrivers : ['Low severity informational items only'],
    };
  }
}
