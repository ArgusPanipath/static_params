/**
 * Enhanced Analyze Controller
 *
 * Supports:
 * - Tiered analysis (quick/standard/deep)
 * - Package name lookup (fetches from npm)
 * - Direct file upload (static analysis only)
 * - Selective rule execution
 */

const npmMetadataService = require("../services/npmMetadataService");
const {
  getApplicableRules,
  executeRule,
  RULE_CATALOG
} = require("../utils/ruleRegistry");

/**
 * Main analysis endpoint
 * POST /api/analyze
 *
 * Body options:
 * 1. { packageName: "express", tier: "standard" }
 * 2. { files: [...], packageJson: {...}, tier: "quick" }
 * 3. { packageName: "lodash", enabledRules: [1,2,5,10] }
 */
exports.analyze = async (req, res) => {
  try {
    const {
      packageName, // Option 1: Analyze published package
      files, // Option 2: Upload files directly
      packageJson, // Required with files
      tier = "standard", // quick | standard | deep | all
      enabledRules // Optional: specific rule IDs to run
    } = req.body;

    // Build analysis context
    let context = {};
    let analysisMode = "unknown";

    if (packageName) {
      // Fetch metadata from npm registry
      analysisMode = "registry";
      context = await buildContextFromRegistry(packageName);
    } else if (files && packageJson) {
      // Use uploaded files (limited to static analysis)
      analysisMode = "upload";
      context = await buildContextFromUpload(files, packageJson);
    } else {
      return res.status(400).json({
        error: "Must provide either 'packageName' or both 'files' and 'packageJson'",
        examples: {
          registry: { packageName: "express", tier: "standard" },
          upload: { files: [], packageJson: {}, tier: "quick" }
        }
      });
    }

    // Select rules to run
    const rulesToRun = selectRules(context, tier, enabledRules);

    // Execute rules with error isolation
    const results = await executeRules(rulesToRun, context);

    // Calculate risk score
    const riskAnalysis = calculateRiskScore(results);

    // Build response
    res.json({
      package: context.packageName || packageJson?.name || "unknown",
      version: context.latestVersion || packageJson?.version,
      analyzedAt: new Date().toISOString(),
      analysisMode,
      tier,
      rulesExecuted: results.length,
      rulesSucceeded: results.filter(r => r.status === "success").length,
      rulesFailed: results.filter(r => r.status === "error").length,
      rulesSkipped: results.filter(r => r.status === "skipped").length,
      ...riskAnalysis,
      results
    });
  } catch (error) {
    console.error("Analysis error:", error);
    res.status(500).json({
      error: error.message,
      stack: process.env.NODE_ENV === "development" ? error.stack : undefined
    });
  }
};

/**
 * Quick health check - shows available rules
 * GET /api/analyze/rules
 */
exports.listRules = (req, res) => {
  const rules = Object.entries(RULE_CATALOG).map(([id, meta]) => ({
    id: parseInt(id),
    name: meta.name,
    tier: meta.tier,
    priority: meta.priority,
    requires: meta.requires,
    enabled: meta.enabled !== false
  }));

  res.json({
    totalRules: rules.length,
    enabledRules: rules.filter(r => r.enabled).length,
    tiers: {
      static: rules.filter(r => r.tier === "static").length,
      metadata: rules.filter(r => r.tier === "metadata").length,
      behavioral: rules.filter(r => r.tier === "behavioral").length,
      sandbox: rules.filter(r => r.tier === "sandbox").length
    },
    rules
  });
};

/**
 * Build analysis context from npm registry
 */
async function buildContextFromRegistry(packageName) {
  const packageDoc = await npmMetadataService.getPackageMetadata(packageName);
  const context = npmMetadataService.extractAnalysisData(packageDoc);

  // Optionally fetch GitHub stats for rule 28
  if (context.repository) {
    const repoUrl =
      typeof context.repository === "string"
        ? context.repository
        : context.repository.url;

    context.githubStats = await npmMetadataService.getGitHubStats(repoUrl);
  }

  // Fetch popular packages list for rule 23 (typosquatting)
  context.popularPackages = await npmMetadataService.getPopularPackages();

  // Fetch download stats (rule 28)
  context.weeklyDownloads = await npmMetadataService.getWeeklyDownloads(
    packageName
  );

  // Normalize GitHub stats for rule 28
  context.githubStars = context.githubStats?.stars ?? 0;
  context.githubForks = context.githubStats?.forks ?? 0;
  context.githubIssues = context.githubStats?.openIssues ?? 0;
  context.repoExists = context.githubStats ? true : false;

  // Ensure packageSize is present for rule 21
  if (context.packageSize == null) {
    context.packageSize = 0;
  }

  return context;
}

/**
 * Build analysis context from uploaded files
 */
async function buildContextFromUpload(files, packageJson) {
  let context = {
    files,
    packageJson,
    packageName: packageJson.name,
    latestVersion: packageJson.version,
    description: packageJson.description,
    // Defaults to allow all rules to execute even if registry fetch fails
    readme: "",
    versionHistory: [
      {
        version: packageJson.version,
        publishedAt: new Date().toISOString(),
        dependencies: packageJson.dependencies || {},
        devDependencies: packageJson.devDependencies || {},
        scripts: packageJson.scripts || {},
        license: packageJson.license
      }
    ],
    publishTimeline: {
      created: new Date().toISOString(),
      modified: new Date().toISOString(),
      [packageJson.version]: new Date().toISOString()
    },
    packageSize: 0,
    popularPackages: [
      "react",
      "vue",
      "angular",
      "express",
      "lodash",
      "axios",
      "webpack",
      "typescript",
      "eslint",
      "jest"
    ],
    weeklyDownloads: 0,
    githubStars: 0,
    githubForks: 0,
    githubIssues: 0,
    repoExists: false
    // Limited metadata - extended below if registry info is available
  };

  if (packageJson?.name) {
    try {
      const registryContext = await buildContextFromRegistry(packageJson.name);
      context = {
        ...registryContext,
        ...context,
        packageJson: {
          ...registryContext.packageJson,
          ...packageJson
        }
      };
    } catch (error) {
      // Keep upload analysis working even if registry fetch fails
      context.registryError = error.message;
    }
  }

  return context;
}

/**
 * Select which rules to run based on tier and available data
 */
function selectRules(context, tier, enabledRules) {
  // If specific rules requested, use those
  if (enabledRules && Array.isArray(enabledRules)) {
    return enabledRules
      .map(id => ({ id, meta: RULE_CATALOG[id] }))
      .filter(({ meta }) => meta && meta.enabled !== false);
  }

  const normalizedTier = (tier || "standard").toLowerCase();

  // Otherwise, select by tier
  let applicableRules = {};

  if (normalizedTier === "quick") {
    applicableRules = getApplicableRules(context, "static");
  } else if (normalizedTier === "standard") {
    const all = getApplicableRules(context, "all");
    applicableRules = Object.entries(all)
      .filter(([, meta]) => meta.tier !== "behavioral" && meta.tier !== "sandbox")
      .reduce((acc, [id, meta]) => {
        acc[id] = meta;
        return acc;
      }, {});
  } else if (normalizedTier === "deep" || normalizedTier === "all") {
    applicableRules = getApplicableRules(context, "all");
  } else {
    // Fallback: pass through for any unexpected values
    applicableRules = getApplicableRules(context, normalizedTier);
  }

  return Object.entries(applicableRules).map(([id, meta]) => ({
    id,
    meta
  }));
}

/**
 * Execute all selected rules with error isolation
 */
async function executeRules(rulesToRun, context) {
  const results = [];

  for (const { id, meta } of rulesToRun) {
    // Check if we have required inputs
    const missingInputs = meta.requires.filter(field => {
      const value = context[field];
      if (Array.isArray(value)) return value.length === 0;
      if (typeof value === "object" && value !== null)
        return Object.keys(value).length === 0;
      return value === undefined || value === null;
    });

    if (missingInputs.length > 0) {
      results.push({
        ruleId: parseInt(id),
        name: meta.name,
        status: "skipped",
        reason: `Missing required inputs: ${missingInputs.join(", ")}`
      });
      continue;
    }

    // Execute rule
    const result = await executeRule(id, context);
    results.push(result);
  }

  return results;
}

/**
 * Calculate overall risk score and verdict
 */
function calculateRiskScore(results) {
  let riskScore = 0;
  let criticalFindings = 0;
  let mediumFindings = 0;
  let lowFindings = 0;

  for (const r of results) {
    if (r.status !== "success") continue;

    for (const f of r.findings || []) {
      const severity = (f.severity || "").toUpperCase();
      if (severity === "CRITICAL" || severity === "HIGH") {
        criticalFindings++;
        riskScore += 3;
      } else if (severity === "MEDIUM") {
        mediumFindings++;
        riskScore += 2;
      } else if (severity === "LOW" || severity === "INFO") {
        lowFindings++;
        riskScore += 1;
      }
    }
  }

  // Map risk score to verdict
  let verdict = "SAFE";
  if (riskScore >= 10) verdict = "CRITICAL";
  else if (riskScore >= 6) verdict = "HIGH";
  else if (riskScore >= 3) verdict = "MEDIUM";

  return {
    verdict,
    riskScore,
    totalFindings: criticalFindings + mediumFindings + lowFindings,
    criticalFindings,
    mediumFindings,
    lowFindings,
    safe: verdict === "SAFE"
  };
}
