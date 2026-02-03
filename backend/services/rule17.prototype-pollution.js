// services/rule17.prototype-pollution.js

const BUILTIN_PROTOTYPES = [
  "Object",
  "Array",
  "Function",
  "String",
  "Number",
  "Boolean",
  "Date",
  "RegExp",
  "Promise",
  "Map",
  "Set"
];

module.exports = {
  ruleId: 17,
  severity: "HIGH",
  requires: ["sourceCode"],

  run: ({ sourceCode }) => {
    if (!sourceCode || typeof sourceCode !== "string") return [];

    const findings = [];

    // 1️⃣ Direct prototype assignment
    const directPrototypeRegex =
      new RegExp(`(${BUILTIN_PROTOTYPES.join("|")})\\.prototype\\s*\\.`, "g");

    if (directPrototypeRegex.test(sourceCode)) {
      findings.push({
        rule: 17,
        severity: "HIGH",
        message: "Direct modification of built-in prototype detected"
      });
    }

    // 2️⃣ __proto__ pollution
    if (/(__proto__)\s*[\[\]\.]/.test(sourceCode)) {
      findings.push({
        rule: 17,
        severity: "HIGH",
        message: "__proto__ manipulation detected"
      });
    }

    // 3️⃣ Object.defineProperty on prototypes
    const definePropertyRegex =
      /Object\.define(Propert(y|ies))\s*\(\s*([A-Za-z]+)\.prototype/i;

    if (definePropertyRegex.test(sourceCode)) {
      findings.push({
        rule: 17,
        severity: "HIGH",
        message: "Prototype modification via Object.defineProperty detected"
      });
    }

    // 4️⃣ Computed prototype property assignment
    if (
      /\.prototype\s*\[\s*['"`]?[A-Za-z0-9_]+['"`]?\s*\]/.test(sourceCode)
    ) {
      findings.push({
        rule: 17,
        severity: "INFO",
        message: "Computed property assignment on prototype detected"
      });
    }

    return findings;
  }
};
