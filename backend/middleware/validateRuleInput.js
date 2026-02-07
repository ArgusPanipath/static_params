/**
 * Input Validation Middleware
 * 
 * Validates request body for analysis endpoints
 */

module.exports = (req, res, next) => {
  // Check if body exists
  if (!req.body || Object.keys(req.body).length === 0) {
    return res.status(400).json({
      error: "Request body is required",
      hint: "Send either { packageName: 'express' } or { files: [...], packageJson: {...} }",
      documentation: "/api/analyze/rules"
    });
  }

  // Validate packageName or files+packageJson combination
  const { packageName, files, packageJson } = req.body;

  if (!packageName && !files && !packageJson) {
    return res.status(400).json({
      error: "Must provide either 'packageName' or both 'files' and 'packageJson'",
      received: Object.keys(req.body),
      examples: {
        byName: {
          packageName: "express",
          tier: "standard"
        },
        byUpload: {
          files: [{ path: "index.js", content: "..." }],
          packageJson: { name: "my-package", version: "1.0.0" }
        }
      }
    });
  }

  // If files provided, packageJson is required
  if (files && !packageJson) {
    return res.status(400).json({
      error: "When providing 'files', 'packageJson' is also required",
      hint: "packageJson should contain at least { name, version }"
    });
  }

  // If packageJson provided, files should also be provided (unless packageName is present)
  if (packageJson && !files && !packageName) {
    return res.status(400).json({
      error: "When providing 'packageJson', also provide 'files' or 'packageName'",
      hint: "packageJson alone is not sufficient for analysis"
    });
  }

  // Validate files array structure if present
  if (files) {
    if (!Array.isArray(files)) {
      return res.status(400).json({
        error: "'files' must be an array",
        received: typeof files,
        example: [
          { path: "index.js", content: "console.log('hello');" },
          { path: "lib/util.js", content: "module.exports = {};" }
        ]
      });
    }

    const invalidFiles = files.filter(f => !f.path || !f.content);
    if (invalidFiles.length > 0) {
      return res.status(400).json({
        error: "Each file must have 'path' and 'content' properties",
        invalidFiles: invalidFiles.map((f, i) => ({ index: i, file: f }))
      });
    }
  }

  // Validate packageJson structure if present
  if (packageJson) {
    if (typeof packageJson !== 'object' || Array.isArray(packageJson)) {
      return res.status(400).json({
        error: "'packageJson' must be an object",
        received: Array.isArray(packageJson) ? 'array' : typeof packageJson
      });
    }

    if (!packageJson.name || !packageJson.version) {
      return res.status(400).json({
        error: "'packageJson' must contain at least 'name' and 'version'",
        received: Object.keys(packageJson),
        example: {
          name: "my-package",
          version: "1.0.0",
          description: "Optional description",
          dependencies: {}
        }
      });
    }
  }

  // Validate tier if provided
  const { tier } = req.body;
  if (tier && !['quick', 'standard', 'deep', 'all'].includes(tier)) {
    return res.status(400).json({
      error: "Invalid tier value",
      received: tier,
      validOptions: ['quick', 'standard', 'deep', 'all'],
      descriptions: {
        quick: "Static rules only (fastest)",
        standard: "Static + metadata rules",
        deep: "All rules including behavioral analysis",
        all: "Alias for 'deep'"
      }
    });
  }

  // Validate enabledRules if provided
  const { enabledRules } = req.body;
  if (enabledRules) {
    if (!Array.isArray(enabledRules)) {
      return res.status(400).json({
        error: "'enabledRules' must be an array of rule IDs",
        received: typeof enabledRules,
        example: [1, 2, 5, 10, 15]
      });
    }

    const invalidRuleIds = enabledRules.filter(id => 
      typeof id !== 'number' || id < 1 || id > 32
    );
    
    if (invalidRuleIds.length > 0) {
      return res.status(400).json({
        error: "Invalid rule IDs",
        invalidIds: invalidRuleIds,
        hint: "Rule IDs must be numbers between 1 and 32"
      });
    }
  }

  next();
};