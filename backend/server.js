const express = require("express");
const loadRules = require("./utils/loadRules");

const app = express();
app.use(express.json());

// 🔥 Auto-load all rules from services/
const rules = loadRules();

app.post("/analyze", (req, res) => {
  const findings = [];

  for (const rule of rules) {
    // Collect only what the rule needs
    const input = {};
    for (const key of rule.requires) {
      input[key] = req.body[key];
    }

    const result = rule.run(input);
    if (Array.isArray(result) && result.length > 0) {
      findings.push(...result);
    }
  }

  res.json({
    scanned: true,
    safe: findings.every(f => f.severity !== "HIGH"),
    findingsCount: findings.length,
    findings
  });
});

app.listen(5000, () => {
  console.log("Analyzer running on port 5000");
});




// const express = require("express");
// const typosquat = require("./services/typosquat.service");
// const abandoned = require("./services/abandoned.service");

// const app = express();
// app.use(express.json());

// app.post("/analyze", (req, res) => {
//   const { packageName, metadata } = req.body;

//   const findings = [];

//   // Rule 23 – Typosquatting
//   findings.push(...typosquat(packageName));

//   // Rule 24 – Abandoned project resurrection
//   if (metadata) {
//     findings.push(...abandoned(metadata));
//   }

//   res.json({
//     scanned: true,
//     input: packageName,
//     safe: findings.every(f => f.severity !== "HIGH"),
//     findingsCount: findings.length,
//     findings
//   });
// });

// app.listen(5000, () => {
//   console.log("Security analyzer running on port 5000");
// });
