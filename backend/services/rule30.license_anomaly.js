/**
 * Rule 30: License Anomaly Detection
 * Emits HIGH when license changes occur in non-breaking releases.
 */

// NOTE:-✅ Required inputs (engine responsibility)

// Your engine (or Golem ledger integration) must already provide:

// {
//   previousLicense: string | null,
//   currentLicense: string | null,
//   versionBump: "patch" | "minor" | "major"
// }


// No guessing inside the rule.

module.exports = {
  ruleId: 30,
  severity: "HIGH",
  requires: [
    "previousLicense",
    "currentLicense",
    "versionBump"
  ],

  run: ({
    previousLicense,
    currentLicense,
    versionBump
  }) => {
    if (!previousLicense || !currentLicense) return [];

    // No change → safe
    if (previousLicense === currentLicense) return [];

    // License change only suspicious for patch/minor
    if (versionBump !== "patch" && versionBump !== "minor") {
      return [];
    }

    const restrictiveLicenses = [
      /custom/i,
      /proprietary/i,
      /non-commercial/i,
      /source-available/i,
      /elastic/i,
      /sspl/i
    ];

    const isRestrictive = restrictiveLicenses.some(r =>
      r.test(currentLicense)
    );

    if (isRestrictive) {
      return [{
        rule: 30,
        severity: "HIGH",
        message:
          "License changed to restrictive/custom license in non-breaking release"
      }];
    }

    return [];
  }
};
