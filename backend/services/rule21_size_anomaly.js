// services/rule21.size-anomaly.js

const categoryStats = {
  "date-formatter": { avg: 10 * 1024, std: 5 * 1024 },      // ~10 KB
  "react-framework": { avg: 5 * 1024 * 1024, std: 2 * 1024 * 1024 }, // ~5 MB
  "utility": { avg: 50 * 1024, std: 30 * 1024 },            // ~50 KB
  "cli-tool": { avg: 2 * 1024 * 1024, std: 1 * 1024 * 1024 } // ~2 MB
};

module.exports = {
  ruleId: 21,
  severity: "HIGH",
  requires: ["packageSize", "category"],

  run: ({ packageSize, category }) => {
    if (!packageSize || !category) return [];

    const stats = categoryStats[category];
    if (!stats) return [];

    const { avg, std } = stats;

    const upperBound = avg + 2 * std;
    const lowerBound = avg - 2 * std;

    // Extra hard rule: 10x deviation
    if (packageSize > avg * 10) {
      return [{
        rule: 21,
        severity: "HIGH",
        message: `Package size (${packageSize} bytes) is abnormally large for ${category}`
      }];
    }

    if (packageSize < avg / 10) {
      return [{
        rule: 21,
        severity: "HIGH",
        message: `Package size (${packageSize} bytes) is abnormally small for ${category}`
      }];
    }

    // Statistical deviation rule
    if (packageSize > upperBound || packageSize < lowerBound) {
      return [{
        rule: 21,
        severity: "INFO",
        message: `Package size deviates from expected range for ${category}`
      }];
    }

    return [];
  }
};
