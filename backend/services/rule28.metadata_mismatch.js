/**
 * Rule 28: Project Metadata Mismatch
 * Emits HIGH when download stats vastly exceed social proof.
 */

module.exports = {
  ruleId: 28,
  severity: "HIGH",
  requires: [
    "weeklyDownloads",
    "githubStars",
    "githubForks",
    "githubIssues",
    "repoExists"
  ],

  run: ({
    weeklyDownloads,
    githubStars,
    githubForks,
    githubIssues,
    repoExists
  }) => {
    // Basic sanity
    if (!weeklyDownloads || weeklyDownloads < 1000) return [];

    // Missing or broken repo is already suspicious
    if (repoExists === false) {
      return [{
        rule: 28,
        severity: "HIGH",
        message: "High download count with missing or invalid source repository"
      }];
    }

    // If GitHub data is unavailable, do not guess
    if (
      githubStars == null ||
      githubForks == null ||
      githubIssues == null
    ) {
      return [];
    }

    // Core heuristic
    const stars = Math.max(githubStars, 1); // avoid divide-by-zero
    const downloadToStarRatio = weeklyDownloads / stars;

    if (
      downloadToStarRatio > 10000 &&
      githubForks === 0 &&
      githubIssues === 0
    ) {
      return [{
        rule: 28,
        severity: "HIGH",
        message:
          "Download count vastly exceeds social activity (possible artificial inflation)"
      }];
    }

    return [];
  }
};
