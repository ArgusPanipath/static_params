// test/rule22.test.js

const rule22 = require("../services/rule22.conditional-deps");

const testCases = [
  {
    name: "Linux-specific dependency",
    code: `
      const os = require('os');
      if (os.platform() === 'linux') {
        require('malicious-linux-package');
      }
    `
  },
  {
    name: "Env-based dependency",
    code: `
      if (process.env.NODE_ENV === 'production') {
        require('prod-only-backdoor');
      }
    `
  },
  {
    name: "Safe unconditional require",
    code: `
      const express = require('express');
      require('dotenv').config();
    `
  },
  {
    name: "Process platform check",
    code: `
      if (process.platform === 'win32') {
        require('windows-helper');
      }
    `
  }
];

testCases.forEach(tc => {
  const findings = rule22.run({ sourceCode: tc.code });

  const safe = findings.every(f => f.severity !== "HIGH");

  console.log(`${tc.name} → safe: ${safe}`);

  if (findings.length > 0) {
    console.log("  findings:", findings);
  }
});
