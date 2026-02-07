/**
 * Rule 29: Sensitive Keyword String Search
 * Emits HIGH when sensitive identifiers are sent over network calls.
 */

module.exports = {
  ruleId: 29,
  severity: "HIGH",
  requires: ["sourceCode"],

  run: ({ sourceCode }) => {
    if (!sourceCode || typeof sourceCode !== "string") return [];

    // Sensitive identifiers (IAM / secrets / credentials)
    const sensitiveKeywords = [
      /AWS_SECRET_ACCESS_KEY/i,
      /AWS_ACCESS_KEY_ID/i,
      /SECRET/i,
      /TOKEN/i,
      /AUTHORIZATION/i,
      /PASSWD/i,
      /PASSWORD/i,
      /ID_RSA/i,
      /\.env/i,
      /SHADOW/i
    ];

    // Outgoing network usage
    const networkSinks = [
      /fetch\s*\(/,
      /axios\./,
      /http\.request/,
      /https\.request/,
      /net\.connect/,
      /socket\.write/
    ];

    const hasSensitive = sensitiveKeywords.some(r => r.test(sourceCode));
    if (!hasSensitive) return [];

    const hasNetwork = networkSinks.some(r => r.test(sourceCode));
    if (!hasNetwork) return [];

    return [{
      rule: 29,
      severity: "HIGH",
      message: "Sensitive credential-related data used in network operation"
    }];
  }
};
