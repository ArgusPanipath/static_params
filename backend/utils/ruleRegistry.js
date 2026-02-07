/**
 * Enhanced Rule Registry with Lazy Loading and Metadata
 *
 * This registry categorizes rules by tier and defines their requirements,
 * preventing server crashes from missing dependencies.
 */

const RULE_CATALOG = {
  // =============================================
  // TIER 1: STATIC ANALYSIS (Always Safe)
  // =============================================
  1: {
    name: "Entropy Analysis",
    tier: "static",
    priority: "high",
    requires: ["files"],
    description: "Detects obfuscated code via Shannon entropy",
    loader: () => require("../services/rule01_entropy")
  },

  2: {
    name: "Dangerous API Detection",
    tier: "static",
    priority: "high",
    requires: ["files"],
    description: "Scans for eval(), exec(), child_process",
    loader: () => require("../services/rule02_dangerous_api")
  },

  3: {
    name: "Code Diff Analysis",
    tier: "static",
    priority: "high",
    requires: ["files", "packageJson"],
    description: "Compares versions for suspicious changes",
    loader: () => require("../services/rule03_code_diff")
  },

  5: {
    name: "Network Destination Analysis",
    tier: "static",
    priority: "medium",
    requires: ["files"],
    description: "Tracks HTTP/DNS requests",
    loader: () => require("../services/rule05_network_destinations")
  },

  6: {
    name: "File System Access Patterns",
    tier: "static",
    priority: "medium",
    requires: ["files"],
    description: "Detects reads from sensitive paths",
    loader: () => require("../services/rule06_filesystem_access")
  },

  7: {
    name: "Install Script Analysis",
    tier: "static",
    priority: "medium",
    requires: ["packageJson"],
    description: "Checks postinstall scripts",
    loader: () => require("../services/rule07_install_scripts")
  },

  8: {
    name: "Dependency Confusion Detection",
    tier: "static",
    priority: "medium",
    requires: ["packageJson"],
    description: "Checks for naming conflicts",
    loader: () => require("../services/rule08_dependency_confusion")
  },

  // =============================================
  // TIER 2: METADATA ANALYSIS (Requires npm data)
  // =============================================
  9: {
    name: "Version Anomaly Detection",
    tier: "metadata",
    priority: "medium",
    requires: ["versionHistory", "publishTimeline"],
    description: "Flags unusual versioning patterns",
    loader: () => require("../services/rule09_version_anomaly")
  },

  10: {
    name: "README Deception",
    tier: "metadata",
    priority: "medium",
    requires: ["readme", "files", "packageJson"],
    dependencies: ["natural"], // NLP library
    description: "Compares claims vs actual behavior",
    loader: () => require("../services/rule10_readme_deception")
  },

  11: {
    name: "Binary/Native Module Detection",
    tier: "metadata",
    priority: "low",
    requires: ["files", "packageJson"],
    description: "Flags compiled binaries",
    loader: () => require("../services/rule11_binary_detection")
  },

  12: {
    name: "Crypto/Miner Detection",
    tier: "metadata",
    priority: "low",
    requires: ["files"],
    description: "Scans for cryptocurrency mining",
    loader: () => require("../services/rule12_crypto_miner")
  },

  13: {
    name: "Time Bomb Detection",
    tier: "metadata",
    priority: "high",
    requires: ["files"],
    description: "Scans for delayed activation logic",
    loader: () => require("../services/rule13_time_bomb")
  },

  14: {
    name: "Environment Evasion Detection",
    tier: "metadata",
    priority: "high",
    requires: ["files"],
    description: "Detects sandbox detection code",
    loader: () => require("../services/rule14_environment_evasion")
  },

  15: {
    name: "Unicode/Homoglyph Obfuscation",
    tier: "metadata",
    priority: "high",
    requires: ["files"],
    description: "Detects lookalike characters",
    loader: () => require("../services/rule15_unicode_obfuscation")
  },

  16: {
    name: "Dynamic Import Patterns",
    tier: "metadata",
    priority: "high",
    requires: ["files"],
    description: "Detects computed import paths",
    loader: () => require("../services/rule16_dynamic_import")
  },

  17: {
    name: "Prototype Pollution",
    tier: "metadata",
    priority: "medium-high",
    requires: ["files"],
    description: "Detects prototype modifications",
    loader: () => require("../services/rule17_prototype_pollution")
  },

  18: {
    name: "WebAssembly/Binary Payload",
    tier: "metadata",
    priority: "medium-high",
    requires: ["files"],
    description: "Detects WASM and base64 binaries",
    loader: () => require("../services/rule18_wasm_detection")
  },

  19: {
    name: "Regex Complexity (ReDoS)",
    tier: "metadata",
    priority: "medium",
    requires: ["files"],
    description: "Detects dangerous regex patterns",
    loader: () => require("../services/rule19_regex_complexity")
  },

  20: {
    name: "Native Addon Patterns",
    tier: "metadata",
    priority: "medium",
    requires: ["files", "packageJson"],
    description: "Analyzes .node files and build scripts",
    loader: () => require("../services/rule20_native_addons")
  },

  21: {
    name: "Package Size Anomaly",
    tier: "metadata",
    priority: "medium",
    requires: ["files", "packageJson", "packageSize"],
    description: "Flags unusual package sizes",
    loader: () => require("../services/rule21_size_anomaly")
  },

  22: {
    name: "Conditional Dependency Loading",
    tier: "metadata",
    priority: "medium",
    requires: ["files"],
    description: "Detects platform-specific requires",
    loader: () => require("../services/rule22_conditional_deps")
  },

  23: {
    name: "Typosquatting Detection",
    tier: "metadata",
    priority: "high",
    requires: ["packageName", "popularPackages"],
    description: "Calculates name similarity distance",
    loader: () => require("../services/rule23_typosquatting")
  },

  24: {
    name: "Abandoned Project Resurrection",
    tier: "metadata",
    priority: "high",
    requires: ["versionHistory", "publishTimeline"],
    description: "Detects dormant account compromise",
    loader: () => require("../services/rule24_resurrection")
  },

  25: {
    name: "Minified Code in Patches",
    tier: "metadata",
    priority: "high",
    requires: ["files", "versionHistory"],
    description: "Identifies suspicious minification",
    loader: () => require("../services/rule25_minified_patches")
  },

  // =============================================
  // TIER 3: BEHAVIORAL ANALYSIS (Heavy/Sandbox)
  // =============================================
  26: {
    name: "Reflective Code Loading",
    tier: "behavioral",
    priority: "medium-high",
    requires: ["files"],
    description: "Detects vm.runInContext and new Function()",
    loader: () => require("../services/rule26_reflective_loading")
  },

  27: {
    name: "Socket/Stream Redirection",
    tier: "behavioral",
    priority: "medium-high",
    requires: ["files"],
    description: "Detects reverse shell patterns",
    loader: () => require("../services/rule27_socket_redirection")
  },

  28: {
    name: "Project Metadata Mismatch",
    tier: "behavioral",
    priority: "medium",
    requires: [
      "weeklyDownloads",
      "githubStars",
      "githubForks",
      "githubIssues",
      "repoExists"
    ],
    dependencies: ["axios"], // For GitHub API
    description: "Cross-references downloads vs GitHub activity",
    loader: () => require("../services/rule28_metadata_mismatch")
  },

  29: {
    name: "Sensitive Keyword Search",
    tier: "behavioral",
    priority: "medium",
    requires: ["files"],
    description: "Scans for hardcoded credentials",
    loader: () => require("../services/rule29_sensitive_keywords")
  },

  30: {
    name: "License Anomaly Detection",
    tier: "behavioral",
    priority: "low-medium",
    requires: ["packageJson", "versionHistory"],
    description: "Detects sudden license changes",
    loader: () => require("../services/rule30_license_anomaly")
  },

  31: {
    name: "Dead Man's Switch",
    tier: "behavioral",
    priority: "high",
    requires: ["files"],
    description: "Detects C2 disconnect triggers",
    loader: () => require("../services/rule31_dead_mans_switch")
  },

  32: {
    name: "Browser API Hijacking",
    tier: "behavioral",
    priority: "medium-high",
    requires: ["files"],
    description: "Detects global API overrides",
    loader: () => require("../services/rule32_browser_hijacking")
  },

  // Sandbox execution (optional, resource-intensive)
  4: {
    name: "Behavioral Sandboxing",
    tier: "sandbox",
    priority: "medium",
    requires: ["files", "packageJson"],
    dependencies: ["dockerode"], // Docker SDK
    description: "Executes package in isolated container",
    loader: () => require("../services/rule04_sandbox"),
    enabled: false // Disabled by default due to cost
  }
};

/**
 * Get rules by tier
 */
function getRulesByTier(tier) {
  return Object.entries(RULE_CATALOG)
    .filter(([, meta]) => meta.tier === tier)
    .reduce((acc, [id, meta]) => {
      acc[id] = meta;
      return acc;
    }, {});
}

/**
 * Get all static rules (always safe to run)
 */
function getStaticRules() {
  return getRulesByTier("static");
}

/**
 * Get rules that can run with given context
 */
function getApplicableRules(context, tier = "all") {
  const tierFilter =
    tier === "all" ? ["static", "metadata", "behavioral"] : [tier];

  return Object.entries(RULE_CATALOG)
    .filter(([id, meta]) => {
      // Skip disabled rules
      if (meta.enabled === false) return false;

      // Check tier
      if (!tierFilter.includes(meta.tier)) return false;

      // Check if all required inputs are present
      return meta.requires.every(field => {
        const value = context[field];
        // Check for non-empty values
        if (Array.isArray(value)) return value.length > 0;
        if (typeof value === "object") return Object.keys(value).length > 0;
        return value !== undefined && value !== null;
      });
    })
    .reduce((acc, [id, meta]) => {
      acc[id] = meta;
      return acc;
    }, {});
}

/**
 * Load and execute a single rule
 */
async function executeRule(ruleId, context) {
  const ruleMeta = RULE_CATALOG[ruleId];

  if (!ruleMeta) {
    throw new Error(`Rule ${ruleId} not found`);
  }

  // Validate required inputs
  const missingInputs = ruleMeta.requires.filter(field => {
    const value = context[field];
    if (Array.isArray(value)) return value.length === 0;
    if (typeof value === "object" && value !== null)
      return Object.keys(value).length === 0;
    return value === undefined || value === null;
  });
  if (missingInputs.length > 0) {
    throw new Error(`Rule ${ruleId} requires: ${missingInputs.join(", ")}`);
  }

  try {
    // Lazy load the rule implementation
    const ruleImpl = ruleMeta.loader();

    const derived = buildDerivedContext(context);

    // Execute with timeout
    const result = await Promise.race([
      Promise.resolve(runRule(ruleImpl, { ...context, ...derived })),
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error("Rule execution timeout")), 30000)
      )
    ]);

    const findings = Array.isArray(result) ? result : result?.findings || [];

    return {
      ruleId: parseInt(ruleId),
      name: ruleMeta.name,
      status: "success",
      findings
    };
  } catch (error) {
    return {
      ruleId: parseInt(ruleId),
      name: ruleMeta.name,
      status: "error",
      error: error.message
    };
  }
}

function buildDerivedContext(context) {
  const files = Array.isArray(context.files) ? context.files : [];
  const fileList = files.map(f => f.path).filter(Boolean);
  const bindingGyp =
    files.find(f => f.path && f.path.endsWith("binding.gyp"))?.content || "";
  const buildScripts = context.packageJson?.scripts
    ? Object.values(context.packageJson.scripts).join(" && ")
    : "";

  return {
    fileList,
    bindingGyp,
    buildScripts
  };
}

function runRule(ruleImpl, context) {
  if (typeof ruleImpl === "function") {
    return ruleImpl(context);
  }

  if (!ruleImpl || typeof ruleImpl.run !== "function") {
    throw new Error("Rule implementation is not executable");
  }

  const requiresSourceCode = Array.isArray(ruleImpl.requires)
    ? ruleImpl.requires.includes("sourceCode")
    : false;

  if (requiresSourceCode && Array.isArray(context.files)) {
    const findings = [];

    for (const file of context.files) {
      const fileContext = {
        ...context,
        sourceCode: file.content || "",
        filePath: file.path
      };
      const result = ruleImpl.run(fileContext);
      const list = Array.isArray(result) ? result : result?.findings || [];

      for (const finding of list) {
        if (finding && !finding.file && file.path) {
          findings.push({ ...finding, file: file.path });
        } else {
          findings.push(finding);
        }
      }
    }

    return findings;
  }

  return ruleImpl.run(context);
}

module.exports = {
  RULE_CATALOG,
  getRulesByTier,
  getStaticRules,
  getApplicableRules,
  executeRule
};
