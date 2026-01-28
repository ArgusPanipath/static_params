/**
 * Rule 07: Install Script Analysis
 * Detects malicious or suspicious install-time scripts
 */

const SUSPICIOUS_COMMANDS = [
    "curl ",
    "wget ",
    "bash",
    "sh ",
    "node -e",
    "eval",
    "chmod",
    "powershell",
    "Invoke-WebRequest"
  ];
  
  module.exports = function rule07_install_scripts({ packageJson }) {
    const findings = [];
  
    if (!packageJson || !packageJson.scripts) {
      return {
        rule: "rule07_install_scripts",
        description: "Detects suspicious npm install scripts",
        findings: [],
        risk: "LOW"
      };
    }
  
    const scripts = packageJson.scripts;
  
    for (const stage of ["preinstall", "install", "postinstall"]) {
      const command = scripts[stage];
      if (!command) continue;
  
      for (const suspicious of SUSPICIOUS_COMMANDS) {
        if (command.includes(suspicious)) {
          findings.push({
            script: stage,
            command,
            severity: "HIGH",
            reason: "Potentially dangerous install-time command detected"
          });
          break;
        }
      }
    }
  
    return {
      rule: "rule07_install_scripts",
      description: "Detects suspicious npm install scripts",
      findings,
      risk: findings.length > 0 ? "HIGH" : "LOW"
    };
  };
  