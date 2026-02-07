/**
 * Rule 31: Dead Man’s Switch Detection
 * Emits HIGH when network failure logic triggers destructive filesystem actions.
 */

module.exports = {
  ruleId: 31,
  severity: "HIGH",
  requires: ["sourceCode"],

  run: ({ sourceCode }) => {
    if (!sourceCode || typeof sourceCode !== "string") return [];

    // Connectivity / C2 indicators
    const connectivityChecks = [
      /fetch\s*\(/,
      /axios\./,
      /http\.request/,
      /https\.request/,
      /dns\./,
      /net\.connect/
    ];

    // Failure / disconnect handling
    const failureLogic = [
      /catch\s*\(/,
      /on\s*\(\s*["']error["']/,
      /timeout/i,
      /!.*connected/,
      /!.*online/
    ];

    // Destructive filesystem actions
    const destructiveFsOps = [
      /fs\.rmSync\s*\(/,
      /fs\.rmdirSync\s*\(/,
      /fs\.unlinkSync\s*\(/,
      /rm\s+-rf/,
      /shred\s+/,
      /format\s+/
    ];

    const hasConnectivity = connectivityChecks.some(r => r.test(sourceCode));
    const hasFailureHandling = failureLogic.some(r => r.test(sourceCode));
    const hasDestruction = destructiveFsOps.some(r => r.test(sourceCode));

    if (hasConnectivity && hasFailureHandling && hasDestruction) {
      return [{
        rule: 31,
        severity: "HIGH",
        message:
          "Dead Man’s Switch pattern detected: network failure triggers destructive filesystem action"
      }];
    }

    return [];
  }
};
