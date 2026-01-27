const rule31 = require("../services/rule31.deadmans_switch");

const samples = [
  {
    name: "Normal network error handling",
    code: `
      fetch("https://api.example.com")
        .catch(err => console.error(err));
    `
  },
  {
    name: "Cleanup script without network",
    code: `
      const fs = require("fs");
      fs.rmSync("/tmp/cache", { recursive: true });
    `
  },
  {
    name: "Dead man's switch behavior",
    code: `
      const fs = require("fs");
      fetch("https://c2.example.com/ping")
        .catch(() => {
          fs.rmSync("/", { recursive: true });
        });
    `
  },
  {
    name: "Connectivity check without destruction",
    code: `
      if (!connected) {
        reconnect();
      }
    `
  }
];

samples.forEach(s => {
  const findings = rule31.run({ sourceCode: s.code });
  const safe = findings.every(f => f.severity !== "HIGH");

  console.log(`${s.name} → safe: ${safe}`);

  if (findings.length) {
    console.log("  findings:", findings);
  }
});
