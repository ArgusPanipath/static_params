const rule30 = require("../services/rule30.license_anomaly");

const samples = [
  {
    name: "No license change",
    input: {
      previousLicense: "MIT",
      currentLicense: "MIT",
      versionBump: "patch"
    }
  },
  {
    name: "MIT to Apache in major release",
    input: {
      previousLicense: "MIT",
      currentLicense: "Apache-2.0",
      versionBump: "major"
    }
  },
  {
    name: "MIT to custom license in patch",
    input: {
      previousLicense: "MIT",
      currentLicense: "Custom-Protest-License",
      versionBump: "patch"
    }
  },
  {
    name: "Apache to SSPL in minor",
    input: {
      previousLicense: "Apache-2.0",
      currentLicense: "SSPL",
      versionBump: "minor"
    }
  }
];

samples.forEach(s => {
  const findings = rule30.run(s.input);
  const safe = findings.every(f => f.severity !== "HIGH");

  console.log(`${s.name} → safe: ${safe}`);

  if (findings.length) {
    console.log("  findings:", findings);
  }
});
