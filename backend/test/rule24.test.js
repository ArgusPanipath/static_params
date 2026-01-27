const rule24 = require("../services/rule24.abandoned");

const input = {
  metadata: {
    previousVersionDate: "2024-01-01",
    latestVersionDate: "2024-09-01",
    previousMaintainer: "alice",
    currentMaintainer: "bob",
    linesAdded: 5000
  }
};

const findings = rule24.run(input);
console.log(findings.length ? "FLAGGED" : "SAFE", findings);
