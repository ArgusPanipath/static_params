/**
 * Rule 08: Dependency Confusion Detection
 * Detects potentially internal or hijacked package names
 */

const SUSPICIOUS_SCOPES = [
    "@mycompany",
    "@internal",
    "@corp",
    "@company",
    "@private"
  ];
  
  module.exports = function rule08_dependency_confusion({ packageJson }) {
    const findings = [];
  
    if (!packageJson || !packageJson.dependencies) {
      return {
        rule: "rule08_dependency_confusion",
        description: "Detects potential dependency confusion attacks",
        findings: [],
        risk: "LOW"
      };
    }
  
    const dependencies = Object.keys(packageJson.dependencies);
  
    for (const dep of dependencies) {
      if (dep.startsWith("@")) {
        for (const scope of SUSPICIOUS_SCOPES) {
          if (dep.startsWith(scope)) {
            findings.push({
              package: dep,
              severity: "HIGH",
              reason: "Scoped dependency may be internal or susceptible to dependency confusion"
            });
            break;
          }
        }
      }
    }
  
    return {
      rule: "rule08_dependency_confusion",
      description: "Detects potential dependency confusion attacks",
      findings,
      risk: findings.length > 0 ? "HIGH" : "LOW"
    };
  };
  