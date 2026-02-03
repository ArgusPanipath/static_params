// services/rule22.conditional-deps.js

const SUSPICIOUS_CONDITIONS = [
  "os.platform",
  "process.platform",
  "process.env"
];

module.exports = {
  ruleId: 22,
  severity: "HIGH",
  requires: ["sourceCode"],

  run: ({ sourceCode }) => {
    if (!sourceCode || typeof sourceCode !== "string") return [];

    const findings = [];

    // Detect platform / env checks
    const conditionRegex =
      /(if\s*\(|\?\s*|&&|\|\|).*?(os\.platform\(\)|process\.platform|process\.env\.[A-Z_]+)/gi;

    // Detect require inside conditional blocks
    const requireRegex =
      /require\s*\(\s*['"`]([^'"`]+)['"`]\s*\)/gi;

    const conditionMatches = sourceCode.match(conditionRegex);
    const requireMatches = [...sourceCode.matchAll(requireRegex)];

    if (conditionMatches && requireMatches.length > 0) {
      requireMatches.forEach(match => {
        findings.push({
          rule: 22,
          severity: "HIGH",
          message: `Conditional dependency loading detected: require("${match[1]}") based on platform or environment`
        });
      });
    }

    return findings;
  }
};
