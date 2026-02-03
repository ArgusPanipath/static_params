const popularRaw = require("../data/top-packages.json");
const levenshtein = require("../utils/levenshtein");

const normalize = name =>
  name.toLowerCase().replace(/[@/_\-].*$/, "");

const popular = popularRaw.map(normalize);

module.exports = {
  ruleId: 23,
  severity: "HIGH",
  requires: ["packageName"],

  run: ({ packageName }) => {
    if (!packageName) return [];

    const input = normalize(packageName);

    // Exact match → safe
    if (popular.includes(input)) return [];

    const matches = popular
      .map(pkg => ({
        pkg,
        distance: levenshtein(input, pkg)
      }))
      .filter(r => r.distance > 0 && r.distance <= 2);

    if (matches.length > 0) {
      return matches.map(r => ({
        rule: 23,
        severity: "HIGH",
        message: `Possible typosquatting of "${r.pkg}"`
      }));
    }

    return [{
      rule: 23,
      severity: "INFO",
      message: "Package not in popular DB, manual review recommended"
    }];
  }
};

