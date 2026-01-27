/**
 * Rule 32: Browser-Side API Hijacking
 * Emits HIGH when global browser APIs are overridden.
 */

module.exports = {
  ruleId: 32,
  severity: "HIGH",
  requires: ["sourceCode"],

  run: ({ sourceCode }) => {
    if (!sourceCode || typeof sourceCode !== "string") return [];

    // High-risk browser globals
    const apiTargets = [
      /window\.fetch\s*=/,
      /fetch\s*=/,
      /window\.XMLHttpRequest\s*=/,
      /XMLHttpRequest\s*=/,
      /window\.ethereum\s*=/,
      /window\.web3\s*=/
    ];

    const definePropertyHijack = [
      /Object\.defineProperty\s*\(\s*window\s*,\s*["']fetch["']/,
      /Object\.defineProperty\s*\(\s*window\s*,\s*["']XMLHttpRequest["']/,
      /Object\.defineProperty\s*\(\s*window\s*,\s*["']ethereum["']/,
      /Object\.defineProperty\s*\(\s*window\s*,\s*["']web3["']/
    ];

    const prototypeHijack = [
      /XMLHttpRequest\.prototype\./,
      /fetch\.prototype\./
    ];

    const hasDirectOverride = apiTargets.some(r => r.test(sourceCode));
    const hasDefineProperty = definePropertyHijack.some(r => r.test(sourceCode));
    const hasPrototypeHijack = prototypeHijack.some(r => r.test(sourceCode));

    if (hasDirectOverride || hasDefineProperty || hasPrototypeHijack) {
      return [{
        rule: 32,
        severity: "HIGH",
        message:
          "Global browser API override detected (possible credential or wallet interception)"
      }];
    }

    return [];
  }
};
