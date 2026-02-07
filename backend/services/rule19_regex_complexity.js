module.exports = {
  ruleId: 19,
  severity: "HIGH",
  requires: ["files"],

  run: ({ files }) => {
    console.log("🔥 RULE 19 EXECUTED, files =", Array.isArray(files));

    const findings = [];
    if (!Array.isArray(files)) return findings;

    const dangerous = /\(([^)]+[+*])\)[+*]/;

    for (const file of files) {
      const content = file.content || "";
      const regexes = content.match(/\/([^\/\\]|\\.)+\/[gimsuy]*/g) || [];

      for (const r of regexes) {
        if (dangerous.test(r)) {
          findings.push({
            type: "REGEX_COMPLEXITY",
            file: file.path,
            pattern: r,
            severity: "HIGH",
            reason: "Potential catastrophic backtracking (ReDoS)"
          });
        }
      }
    }

    return findings;
  }
};
