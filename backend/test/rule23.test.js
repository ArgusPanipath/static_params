const rule23 = require("../services/rule23.typosquat");

const inputs = [
  "request",
  "reqeust",
  "lodas",
  "lodash",
  "axiosss",
  "random-lib"
];

inputs.forEach(pkg => {
  const findings = rule23.run({ packageName: pkg });

  const safe = findings.every(f => f.severity !== "HIGH");

  console.log(
    `Package: ${pkg} → safe: ${safe}`
  );

  if (findings.length > 0) {
    console.log("  findings:", findings);
  }
});
