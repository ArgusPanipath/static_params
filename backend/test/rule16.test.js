// test/rule16.test.js

const rule16 = require("../services/rule16.dynamic-import");

const testCases = [
  {
    name: "Concatenated require",
    code: `
      const cp = require('child' + '_process');
    `
  },
  {
    name: "Base64-decoded import",
    code: `
      import(atob('Y2hpbGRfcHJvY2Vzcw=='));
    `
  },
  {
    name: "Variable-based require",
    code: `
      const mod = process.env.MODULE;
      require(mod);
    `
  },
  {
    name: "Template literal require",
    code: `
      require(\`./plugins/\${name}\`);
    `
  },
  {
    name: "Safe static import",
    code: `
      const fs = require('fs');
      import express from 'express';
    `
  }
];

testCases.forEach(tc => {
  const findings = rule16.run({ sourceCode: tc.code });
  const safe = findings.every(f => f.severity !== "HIGH");

  console.log(`${tc.name} → safe: ${safe}`);

  if (findings.length > 0) {
    console.log("  findings:", findings);
  }
});
