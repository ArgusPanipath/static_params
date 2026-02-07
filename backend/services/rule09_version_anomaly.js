/**
 * Rule 09 – Version Anomaly Detection
 * Priority: LOW–MEDIUM
 */

const fetch = require("node-fetch");

module.exports = {
    ruleId: 9,
    severity: "MEDIUM",
    requires: ["versionHistory"],
  
    run: ({ versionHistory }) => {
      const findings = [];
  
      if (!Array.isArray(versionHistory) || versionHistory.length < 2) {
        return findings;
      }
  
      // Sort by timestamp
      const history = [...versionHistory].sort(
        (a, b) => new Date(a.timestamp) - new Date(b.timestamp)
      );
  
      // 1️⃣ Version velocity (>5 versions in 24h)
      for (let i = 0; i < history.length; i++) {
        const startTime = new Date(history[i].timestamp).getTime();
        let count = 1;
  
        for (let j = i + 1; j < history.length; j++) {
          const diffHours =
            (new Date(history[j].timestamp).getTime() - startTime) /
            (1000 * 60 * 60);
  
          if (diffHours <= 24) count++;
        }
  
        if (count > 5) {
          findings.push({
            rule: 9,
            severity: "MEDIUM",
            message: `Rapid version publishing detected (${count} versions in 24h)`
          });
          break;
        }
      }
  
      // 2️⃣ Semantic version & suspicious jumps
      const isValidSemver = v => /^\d+\.\d+\.\d+$/.test(v);
  
      const parse = v => v.split(".").map(Number);
  
      for (let i = 1; i < history.length; i++) {
        const prev = history[i - 1].version;
        const curr = history[i].version;
  
        if (!isValidSemver(curr)) {
          findings.push({
            rule: 9,
            severity: "LOW",
            message: `Invalid semantic version format: ${curr}`
          });
        }
  
        if (isValidSemver(prev) && isValidSemver(curr)) {
          const [prevMajor] = parse(prev);
          const [currMajor] = parse(curr);
  
          if (currMajor - prevMajor >= 10) {
            findings.push({
              rule: 9,
              severity: "MEDIUM",
              message: `Suspicious version jump from ${prev} to ${curr}`
            });
          }
        }
      }
  
      return findings;
    }
  };
  
  