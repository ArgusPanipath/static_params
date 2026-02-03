// test/rule19.test.js

const rule19 = require("../services/rule19.regex-complexity");

const testCases = [
  {
    name: "Classic ReDoS pattern",
    code: `
      const r = /(a+)+$/;
    `
  },
  {
    name: "Exponential backtracking example",
    code: `
      const r = /^(([a-z])+.)+[A-Z]([a-z])+$/;
    `
  },
  {
    name: "Safe regex",
    code: `
      const r = /^[a-z0-9_-]{3,16}$/;
    `
  },
  {
    name: "Very long regex",
    code: `
      const r = /${"a".repeat(250)}/;
    `
  }
];

testCases.forEach(tc => {
  const findings = rule19.run({ sourceCode: tc.code });
  const safe = findings.every(f => f.severity !== "HIGH");

  console.log(`${tc.name} → safe: ${safe}`);

  if (findings.length > 0) {
    console.log("  findings:", findings);
  }
});
