/**
 * Rule 06: Filesystem Access Analysis
 * Detects access to sensitive filesystem paths
 */

const SENSITIVE_PATH_PATTERNS = [
    "/etc/passwd",
    "/etc/shadow",
    ".ssh",
    ".aws",
    ".npmrc",
    ".env",
    ".git/config",
    "/root",
    "/home",
    "/var/lib",
    "/proc",
    "/sys"
  ];
  
  module.exports = function rule06_filesystem_access({ files }) {
    const findings = [];
  
    if (!Array.isArray(files)) {
      return {
        rule: "rule06_filesystem_access",
        description: "Detects access to sensitive filesystem paths",
        findings: [],
        risk: "LOW"
      };
    }
  
    for (const file of files) {
      const content = file.content || "";
  
      for (const pattern of SENSITIVE_PATH_PATTERNS) {
        if (content.includes(pattern)) {
          findings.push({
            file: file.path,
            path: pattern,
            severity: "HIGH",
            reason: "Access to sensitive filesystem location detected"
          });
        }
      }
    }
  
    return {
      rule: "rule06_filesystem_access",
      description: "Detects access to sensitive filesystem paths",
      findings,
      risk: findings.length > 0 ? "HIGH" : "LOW"
    };
  };
  