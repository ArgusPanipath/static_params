// test/rule17.test.js

const rule17 = require("../services/rule17.prototype-pollution");

const testCases = [
  {
    name: "Object prototype pollution",
    code: `
      Object.prototype.isAdmin = true;
    `
  },
  {
    name: "Array prototype hijack",
    code: `
      Array.prototype.forEach = function() {
        console.log("hijacked");
      };
    `
  },
  {
    name: "__proto__ pollution",
    code: `
      const payload = {};
      payload.__proto__.polluted = true;
    `
  },
  {
    name: "defineProperty on prototype",
    code: `
      Object.defineProperty(Object.prototype, "evil", {
        value: true
      });
    `
  },
  {
    name: "Safe class prototype",
    code: `
      class User {
        isAdmin() { return false; }
      }
    `
  }
];

testCases.forEach(tc => {
  const findings = rule17.run({ sourceCode: tc.code });
  const safe = findings.every(f => f.severity !== "HIGH");

  console.log(`${tc.name} → safe: ${safe}`);

  if (findings.length > 0) {
    console.log("  findings:", findings);
  }
});
