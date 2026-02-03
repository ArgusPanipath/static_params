// services/rule16.dynamic-import.js

module.exports = {
  ruleId: 16,
  severity: "HIGH",
  requires: ["sourceCode"],

  run: ({ sourceCode }) => {
    if (!sourceCode || typeof sourceCode !== "string") return [];

    const findings = [];

    // 1️⃣ require(variable) or require(expression)
    const dynamicRequireRegex =
      /require\s*\(\s*([^'"\s][^)]*)\s*\)/g;

    if (dynamicRequireRegex.test(sourceCode)) {
      findings.push({
        rule: 16,
        severity: "HIGH",
        message: "Dynamic require() with non-literal argument detected"
      });
    }

    // 2️⃣ import(variable or expression)
    const dynamicImportRegex =
      /import\s*\(\s*([^'"\s][^)]*)\s*\)/g;

    if (dynamicImportRegex.test(sourceCode)) {
      findings.push({
        rule: 16,
        severity: "HIGH",
        message: "Dynamic import() with computed path detected"
      });
    }

    // 3️⃣ String concatenation in import paths
    if (/require\s*\(\s*['"`][^'"`]*['"`]\s*\+/.test(sourceCode)) {
      findings.push({
        rule: 16,
        severity: "HIGH",
        message: "String concatenation used in require() path"
      });
    }

    // 4️⃣ Template literals in import paths
    if (/require\s*\(\s*`[^`]*\$\{/.test(sourceCode)) {
      findings.push({
        rule: 16,
        severity: "HIGH",
        message: "Template literal used in require() path"
      });
    }

    // 5️⃣ Base64-decoded import paths
    if (
      /(require|import)\s*\(\s*(atob|Buffer\.from)\(/.test(sourceCode)
    ) {
      findings.push({
        rule: 16,
        severity: "HIGH",
        message: "Obfuscated import path via base64 decoding detected"
      });
    }

    return findings;
  }
};
