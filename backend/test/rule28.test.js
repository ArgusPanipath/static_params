const rule28 = require("../services/rule28.metadata_mismatch");

const samples = [
  {
    name: "Popular legitimate package",
    input: {
      weeklyDownloads: 500000,
      githubStars: 20000,
      githubForks: 3000,
      githubIssues: 120,
      repoExists: true
    }
  },
  {
    name: "High downloads, zero GitHub activity",
    input: {
      weeklyDownloads: 120000,
      githubStars: 0,
      githubForks: 0,
      githubIssues: 0,
      repoExists: true
    }
  },
  {
    name: "Missing repository",
    input: {
      weeklyDownloads: 80000,
      githubStars: null,
      githubForks: null,
      githubIssues: null,
      repoExists: false
    }
  },
  {
    name: "Small project",
    input: {
      weeklyDownloads: 300,
      githubStars: 0,
      githubForks: 0,
      githubIssues: 0,
      repoExists: true
    }
  }
];

samples.forEach(s => {
  const findings = rule28.run(s.input);
  const safe = findings.every(f => f.severity !== "HIGH");

  console.log(`${s.name} → safe: ${safe}`);

  if (findings.length) {
    console.log("  findings:", findings);
  }
});
