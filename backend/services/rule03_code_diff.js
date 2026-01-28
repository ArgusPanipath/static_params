/**
 * Rule 03: Code Diff Analysis
 * Detects suspicious changes between package versions
 */

function diffLines(oldFiles, newFiles) {
    let linesAdded = 0;
    let linesRemoved = 0;
  
    for (const file in newFiles) {
      const oldContent = oldFiles[file] || "";
      const newContent = newFiles[file] || "";
  
      const oldLines = oldContent.split("\n");
      const newLines = newContent.split("\n");
  
      linesAdded += Math.max(0, newLines.length - oldLines.length);
      linesRemoved += Math.max(0, oldLines.length - newLines.length);
    }
  
    return { linesAdded, linesRemoved };
  }
  
  function diffDependencies(oldPkg = {}, newPkg = {}) {
    const oldDeps = oldPkg.dependencies || {};
    const newDeps = newPkg.dependencies || {};
  
    const addedDependencies = [];
  
    for (const dep in newDeps) {
      if (!oldDeps[dep]) {
        addedDependencies.push(dep);
      }
    }
  
    return {
      addedDependencies,
      addedDependencyCount: addedDependencies.length
    };
  }
  
  module.exports = function rule03_code_diff({
    oldFiles = {},
    newFiles = {},
    oldPackageJson = {},
    newPackageJson = {},
    versionChange = "patch"
  }) {
    const findings = [];
  
    const { linesAdded, linesRemoved } = diffLines(oldFiles, newFiles);
    const depDiff = diffDependencies(oldPackageJson, newPackageJson);
  
    let suspicious = false;
  
    // Rule 1: Large change in patch update
    if (versionChange === "patch" && linesAdded > 200) {
      suspicious = true;
    }
  
    // Rule 2: New dependency added in patch/minor update
    if (
      (versionChange === "patch" || versionChange === "minor") &&
      depDiff.addedDependencyCount > 0
    ) {
      suspicious = true;
    }
  
    if (suspicious) {
      findings.push({
        type: "SUSPICIOUS_CODE_DIFF",
        severity: "HIGH",
        details: {
          linesAdded,
          linesRemoved,
          addedDependencies: depDiff.addedDependencies
        },
        reason: "Suspicious code or dependency changes detected between versions"
      });
    }
  
    return {
      rule: "rule03_code_diff",
      description: "Detects suspicious changes between package versions",
      findings,
      risk: findings.length > 0 ? "HIGH" : "LOW"
    };
  };
  