/**
 * Rule Controller
 * 
 * Handles individual rule execution and rule management
 */

const { RULE_CATALOG, executeRule } = require("../utils/ruleRegistry");

/**
 * Run a single rule by ID
 * POST /api/rules/:ruleId
 * 
 * Body: Full context object with all necessary fields
 */
exports.runSingleRule = async (req, res) => {
  try {
    const { ruleId } = req.params;
    const context = req.body;

    // Validate rule exists
    const ruleMeta = RULE_CATALOG[ruleId];
    if (!ruleMeta) {
      return res.status(404).json({
        error: `Rule ${ruleId} not found`,
        availableRules: Object.keys(RULE_CATALOG)
      });
    }

    // Check if rule is enabled
    if (ruleMeta.enabled === false) {
      return res.status(403).json({
        error: `Rule ${ruleId} is disabled`,
        name: ruleMeta.name,
        reason: "Resource-intensive rule disabled by default"
      });
    }

    // Validate required inputs
    const missingInputs = ruleMeta.requires.filter(field => {
      const value = context[field];
      if (Array.isArray(value)) return value.length === 0;
      if (typeof value === 'object' && value !== null) return Object.keys(value).length === 0;
      return !value;
    });

    if (missingInputs.length > 0) {
      return res.status(400).json({
        error: "Missing required inputs",
        ruleId: parseInt(ruleId),
        name: ruleMeta.name,
        missingInputs,
        requiredInputs: ruleMeta.requires,
        example: buildExampleContext(ruleMeta)
      });
    }

    // Execute rule
    const result = await executeRule(ruleId, context);

    res.json(result);

  } catch (error) {
    console.error(`Rule execution error:`, error);
    res.status(500).json({
      error: error.message,
      stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
};

/**
 * Get information about a specific rule
 * GET /api/rules/:ruleId
 */
exports.getRuleInfo = (req, res) => {
  const { ruleId } = req.params;
  
  const ruleMeta = RULE_CATALOG[ruleId];
  if (!ruleMeta) {
    return res.status(404).json({
      error: `Rule ${ruleId} not found`
    });
  }

  res.json({
    id: parseInt(ruleId),
    name: ruleMeta.name,
    description: ruleMeta.description,
    tier: ruleMeta.tier,
    priority: ruleMeta.priority,
    requires: ruleMeta.requires,
    dependencies: ruleMeta.dependencies || [],
    enabled: ruleMeta.enabled !== false,
    exampleContext: buildExampleContext(ruleMeta)
  });
};

/**
 * List all available rules
 * GET /api/rules
 */
exports.listAllRules = (req, res) => {
  const { tier, priority, enabled } = req.query;

  let rules = Object.entries(RULE_CATALOG).map(([id, meta]) => ({
    id: parseInt(id),
    name: meta.name,
    tier: meta.tier,
    priority: meta.priority,
    enabled: meta.enabled !== false
  }));

  // Apply filters
  if (tier) {
    rules = rules.filter(r => r.tier === tier);
  }
  if (priority) {
    rules = rules.filter(r => r.priority === priority);
  }
  if (enabled !== undefined) {
    const isEnabled = enabled === 'true';
    rules = rules.filter(r => r.enabled === isEnabled);
  }

  res.json({
    total: rules.length,
    rules
  });
};

/**
 * Build example context for a rule
 */
function buildExampleContext(ruleMeta) {
  const example = {};
  
  for (const field of ruleMeta.requires) {
    switch (field) {
      case 'files':
        example.files = [
          { path: 'index.js', content: 'console.log("example");' }
        ];
        break;
      case 'packageJson':
        example.packageJson = {
          name: 'example-package',
          version: '1.0.0',
          scripts: { test: 'echo test' }
        };
        break;
      case 'readme':
        example.readme = '# Example Package\\nThis is an example.';
        break;
      case 'versionHistory':
        example.versionHistory = [
          { version: '1.0.0', publishedAt: '2025-01-01T00:00:00Z' }
        ];
        break;
      case 'publishTimeline':
        example.publishTimeline = {
          created: '2025-01-01T00:00:00Z',
          '1.0.0': '2025-01-01T00:00:00Z'
        };
        break;
      case 'packageName':
        example.packageName = 'example-package';
        break;
      case 'popularPackages':
        example.popularPackages = ['react', 'vue', 'express'];
        break;
      default:
        example[field] = `<${field} data>`;
    }
  }
  
  return example;
}