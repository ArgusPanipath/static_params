/**
 * Rule 02: Dangerous API Usage
 * Detects use of risky JavaScript APIs via AST parsing
 */

const parser = require("@babel/parser");

const DANGEROUS_APIS = {
  eval: ["eval", "Function"],
  childProcess: ["exec", "execSync", "spawn", "spawnSync"],
  filesystem: ["readFile", "readFileSync", "writeFile"],
  network: ["fetch", "http", "https", "net", "axios"]
};

function parseAST(code) {
  return parser.parse(code, {
    sourceType: "unambiguous",
    plugins: ["jsx", "dynamicImport"]
  });
}

function detectDangerousCalls(ast) {
  const results = {
    evalCalls: 0,
    childProcessCalls: 0,
    filesystemCalls: 0,
    networkCalls: 0,
    totalDangerousCalls: 0
  };

  function traverse(node) {
    if (!node || typeof node !== "object") return;

    if (node.type === "CallExpression") {
      let calleeName = "";

      if (node.callee.type === "Identifier") {
        calleeName = node.callee.name;
      }

      if (node.callee.type === "MemberExpression") {
        calleeName = node.callee.property?.name || "";
      }

      for (const [category, names] of Object.entries(DANGEROUS_APIS)) {
        if (names.includes(calleeName)) {
          results[`${category}Calls`]++;
          results.totalDangerousCalls++;
        }
      }
    }

    for (const key in node) {
      const child = node[key];
      if (Array.isArray(child)) {
        child.forEach(traverse);
      } else {
        traverse(child);
      }
    }
  }

  traverse(ast.program);
  return results;
}

module.exports = function rule02_dangerous_api({ files }) {
  const findings = [];
  let combined = {
    evalCalls: 0,
    childProcessCalls: 0,
    filesystemCalls: 0,
    networkCalls: 0,
    totalDangerousCalls: 0
  };

  if (!Array.isArray(files)) {
    return {
      rule: "rule02_dangerous_api",
      description: "Detects usage of dangerous JavaScript APIs",
      findings: [],
      risk: "LOW"
    };
  }

  for (const file of files) {
    try {
      const ast = parseAST(file.content || "");
      const result = detectDangerousCalls(ast);

      for (const key in combined) {
        combined[key] += result[key];
      }
    } catch (err) {
      // ignore parse errors
    }
  }

  if (combined.totalDangerousCalls > 0) {
    findings.push({
      type: "DANGEROUS_API_USAGE",
      details: combined,
      severity: "HIGH",
      reason: "Use of potentially dangerous APIs detected"
    });
  }

  return {
    rule: "rule02_dangerous_api",
    description: "Detects usage of dangerous JavaScript APIs",
    findings,
    risk: findings.length > 0 ? "HIGH" : "LOW"
  };
};
