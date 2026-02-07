/**
 * Rule Routes
 * 
 * Individual rule management and execution
 */

const express = require("express");
const { 
  runSingleRule, 
  getRuleInfo, 
  listAllRules 
} = require("../controllers/rule.controller");
const validateRuleInput = require("../middleware/validateRuleInput");

const router = express.Router();

/**
 * GET /api/rules
 * List all available rules (with optional filters)
 * Query params: ?tier=static&priority=high&enabled=true
 */
router.get("/", listAllRules);

/**
 * GET /api/rules/:ruleId
 * Get information about a specific rule
 */
router.get("/:ruleId", getRuleInfo);

/**
 * POST /api/rules/:ruleId
 * Execute a single rule with provided context
 */
router.post("/:ruleId", validateRuleInput, runSingleRule);

module.exports = router;