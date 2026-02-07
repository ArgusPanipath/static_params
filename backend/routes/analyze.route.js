/**
 * Analysis Routes
 * 
 * Main package analysis endpoints
 */

const express = require("express");
const { analyze, listRules } = require("../controllers/analyze.controller");
const validateRuleInput = require("../middleware/validateRuleInput");

const router = express.Router();

/**
 * POST /api/analyze
 * Main analysis endpoint
 * 
 * Accepts:
 * - { packageName: "express", tier: "standard" }
 * - { files: [...], packageJson: {...} }
 * - { packageName: "lodash", enabledRules: [1,2,5] }
 */
router.post("/analyze", validateRuleInput, analyze);

/**
 * GET /api/analyze/rules
 * List all available rules with metadata
 */
router.get("/analyze/rules", listRules);

module.exports = router;