// services/rule19.regex-complexity.js

module.exports = {
  ruleId: 19,
  severity: "HIGH",
  requires: ["sourceCode"],

  run: ({ sourceCode }) => {
    if (!sourceCode || typeof sourceCode !== "string") return [];

    const findings = [];

    // Extract regex literals: /.../flags
    const regexLiteralPattern = /\/([^\/\\]|\\.)+\/[gimsuy]*/g;
    const regexes = sourceCode.match(regexLiteralPattern) || [];

    regexes.forEach(regex => {
      let score = 0;

      // 1️⃣ Nested quantifiers: (a+)+, (.*)+, (.+)+
      if (/\([^\)]*[\+\*][^\)]*\)[\+\*]/.test(regex)) {
        score += 5;
      }

      // 2️⃣ Multiple greedy wildcards
      if (/(.\*){2,}/.test(regex)) {
        score += 3;
      }

      // 3️⃣ Overlapping alternation (a|aa)
      if (/\(([^|]+\|[^|]+)\)/.test(regex)) {
        score += 2;
      }

      // 4️⃣ Excessive backtracking anchors
      if (/(\^\(.*\)\+\$)|(\(\.\*\)\+)/.test(regex)) {
        score += 3;
      }

      // 5️⃣ Long regex
      if (regex.length > 200) {
        score += 2;
      }

      if (score >= 5) {
        findings.push({
          rule: 19,
          severity: "HIGH",
          message: `Suspicious high-complexity regular expression detected (${regex.slice(0, 60)}...)`
        });
      } else if (score >= 3) {
        findings.push({
          rule: 19,
          severity: "INFO",
          message: `Potentially inefficient regular expression detected`
        });
      }
    });

    return findings;
  }
};
