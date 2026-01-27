/**
 * Rule 27: Socket / Stream Redirection
 * Emits HIGH for stream-to-network redirection.
 */

module.exports = {
  ruleId: 27,
  severity: "HIGH",
  requires: ["sourceCode"],

  run: ({ sourceCode }) => {
    if (!sourceCode || typeof sourceCode !== "string") return [];

    const streamSources = [
      /process\.stdin/,
      /process\.stdout/,
      /process\.stderr/,
      /fs\.createReadStream/
    ];

    const networkSinks = [
      /net\.connect/,
      /net\.createConnection/,
      /http\.request/,
      /https\.request/,
      /socket\.write/
    ];

    const bridgingPatterns = [
      /\.pipe\s*\(/,
      /\.on\s*\(\s*["']data["']/
    ];

    const hasSource = streamSources.some(r => r.test(sourceCode));
    const hasSink = networkSinks.some(r => r.test(sourceCode));
    const hasBridge = bridgingPatterns.some(r => r.test(sourceCode));

    if (hasSource && hasSink && hasBridge) {
      return [{
        rule: 27,
        severity: "HIGH",
        message: "Stream redirected into network socket (possible reverse shell)"
      }];
    }

    return [];
  }
};
