const entropy = require("../utils/entropy");

module.exports = {
  ruleId: 25,
  severity: "HIGH",
  requires: ["files"],

  run: ({ files }) => {
    if (!Array.isArray(files)) return [];

    return files
      .filter(
        f =>
          f.lines === 1 &&
          f.size > 5000 &&
          entropy(f.content) > 4.5
      )
      .map(f => ({
        rule: 25,
        severity: "HIGH",
        file: f.path,
        message: "Suspicious minified code detected"
      }));
  }
};
