/**
 * Rule 26: Reflective Code Loading
 * Emits HIGH only for dynamic reflective execution.
 */

module.exports = {
  ruleId: 26,
  severity: "HIGH",
  requires: ["sourceCode"],

  run: ({ sourceCode }) => {
    if (!sourceCode || typeof sourceCode !== "string") return [];

    const execPrimitives = [
      /eval\s*\(/,
      /new\s+Function\s*\(/,
      /vm\.runInThisContext\s*\(/,
      /vm\.runInContext\s*\(/
    ];

    const dynamicIndicators = [
      /fetch\s*\(/,
      /axios\./,
      /http\.request/,
      /https\.request/,
      /Buffer\.from\s*\(/,
      /atob\s*\(/
    ];

    const hasExec = execPrimitives.some(r => r.test(sourceCode));
    const hasDynamicSource = dynamicIndicators.some(r => r.test(sourceCode));

    if (hasExec && hasDynamicSource) {
      return [{
        rule: 26,
        severity: "HIGH",
        message: "Dynamic reflective code execution detected"
      }];
    }

    return [];
  }
};
