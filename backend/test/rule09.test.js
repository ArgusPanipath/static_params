const rule = require("../services/rule09_version_anomaly");

const versionHistory = [
  { version: "1.0.0", timestamp: "2025-01-01T10:00:00Z" },
  { version: "1.0.1", timestamp: "2025-01-01T10:10:00Z" },
  { version: "1.0.2", timestamp: "2025-01-01T10:20:00Z" },
  { version: "1.0.3", timestamp: "2025-01-01T10:30:00Z" },
  { version: "99.99.99", timestamp: "2025-01-01T11:00:00Z" }
];

console.log(rule.run({ versionHistory }));
