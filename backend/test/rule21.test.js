// tests/test21.test.js

const rule21 = require("../services/rule21.size-anomaly");

const testCases = [
  { name: "Normal date formatter", size: 12 * 1024, category: "date-formatter" },
  { name: "Huge date formatter", size: 50 * 1024 * 1024, category: "date-formatter" },
  { name: "Tiny react framework", size: 2 * 1024, category: "react-framework" },
  { name: "Normal utility", size: 40 * 1024, category: "utility" },
  { name: "Oversized CLI tool", size: 30 * 1024 * 1024, category: "cli-tool" },
  { name: "Unknown category", size: 100 * 1024, category: "unknown" }
];

testCases.forEach(tc => {
  const findings = rule21.run({
    packageSize: tc.size,
    category: tc.category
  });

  const safe = findings.every(f => f.severity !== "HIGH");

  console.log(
    `${tc.name} → safe: ${safe}`
  );

  if (findings.length > 0) {
    console.log("  findings:", findings);
  }
});
