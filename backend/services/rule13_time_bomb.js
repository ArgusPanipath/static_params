/**
 * Rule 13: Time Bomb Detection
 * Detects date/time-based conditional logic that activates malicious behavior
 */

const esprima = require('esprima'); // For AST parsing

module.exports = function rule13_time_bomb({ files }) {
    const findings = [];
    
    if (!Array.isArray(files)) {
        return {
            rule: "rule13_time_bomb",
            description: "Detects time-based conditional logic for delayed malicious activation",
            findings: [],
            risk: "LOW"
        };
    }
    
    // Current date for comparison
    const now = new Date();
    const currentTimestamp = now.getTime();
    
    // Future date thresholds (in days)
    const FUTURE_THRESHOLD_DAYS = 30; // Flag dates more than 30 days in future
    const PAST_THRESHOLD_DAYS = -7;   // Flag dates in recent past (recently activated)
    
    function analyzeCode(content, filePath) {
        try {
            const ast = esprima.parseScript(content, { 
                tolerant: true, 
                loc: true,
                range: true 
            });
            
        function traverse(node, depth = 0) {
            if (!node) return;
            
            // Check for Date constructor calls with string arguments
            if (node.type === 'NewExpression' && node.callee.type === 'Identifier' && 
                node.callee.name === 'Date' && node.arguments.length > 0) {
                
                const arg = node.arguments[0];
                if (arg.type === 'Literal' && typeof arg.value === 'string') {
                    try {
                        const dateStr = arg.value;
                        const date = new Date(dateStr);
                        
                        // Check if it's a valid future date
                        if (!isNaN(date.getTime())) {
                            const timeDiff = date.getTime() - currentTimestamp;
                            const daysDiff = timeDiff / (1000 * 60 * 60 * 24);
                            
                            if (daysDiff > FUTURE_THRESHOLD_DAYS || daysDiff < PAST_THRESHOLD_DAYS) {
                                const line = content.substring(
                                    content.lastIndexOf('\n', node.range[0]) + 1,
                                    content.indexOf('\n', node.range[1])
                                ).trim();
                                
                                findings.push({
                                    file: filePath,
                                    type: "SUSPICIOUS_DATE_CREATION",
                                    date_string: dateStr,
                                    parsed_date: date.toISOString(),
                                    days_from_now: daysDiff.toFixed(1),
                                    severity: "MEDIUM",
                                    reason: `Hardcoded ${daysDiff > 0 ? 'future' : 'recent past'} date detected: ${dateStr}`,
                                    snippet: line.substring(0, 100),
                                    line: node.loc.start.line
                                });
                            }
                        }
                    } catch (e) {
                        // Invalid date format, skip
                    }
                }
            }
            
            // Check for comparisons with Date.now() or new Date().getTime()
            if (node.type === 'BinaryExpression' && 
                (node.operator === '>' || node.operator === '>=' || 
                 node.operator === '<' || node.operator === '<=')) {
                
                let dateNode = null;
                let comparisonValue = null;
                
                // Check left side for Date operations, right side for value
                if (isDateExpression(node.left)) {
                    dateNode = node.left;
                    comparisonValue = extractNumericValue(node.right);
                } 
                // Check right side for Date operations, left side for value
                else if (isDateExpression(node.right)) {
                    dateNode = node.right;
                    comparisonValue = extractNumericValue(node.left);
                }
                
                if (dateNode && comparisonValue !== null) {
                    // Check if comparison value is a future timestamp
                    if (comparisonValue > currentTimestamp) {
                        const daysFuture = (comparisonValue - currentTimestamp) / (1000 * 60 * 60 * 24);
                        
                        if (daysFuture > FUTURE_THRESHOLD_DAYS) {
                            const line = content.substring(
                                content.lastIndexOf('\n', node.range[0]) + 1,
                                content.indexOf('\n', node.range[1])
                            ).trim();
                            
                            findings.push({
                                file: filePath,
                                type: "FUTURE_DATE_COMPARISON",
                                comparison_operator: node.operator,
                                future_timestamp: comparisonValue,
                                future_date: new Date(comparisonValue).toISOString(),
                                days_from_now: daysFuture.toFixed(1),
                                severity: "HIGH",
                                reason: `Comparison with future timestamp ${daysFuture.toFixed(1)} days from now`,
                                snippet: line.substring(0, 100),
                                line: node.loc.start.line
                            });
                        }
                    }
                }
            }
            
            // Check for setTimeout/setInterval with suspicious delays
            if (node.type === 'CallExpression') {
                const calleeName = getCalleeName(node.callee);
                if (calleeName === 'setTimeout' || calleeName === 'setInterval') {
                    if (node.arguments.length >= 2) {
                        const delayArg = node.arguments[0];
                        const delayValue = extractNumericValue(delayArg);
                        
                        // Check for suspiciously long delays (more than 30 days)
                        if (delayValue !== null && delayValue > 30 * 24 * 60 * 60 * 1000) {
                            const line = content.substring(
                                content.lastIndexOf('\n', node.range[0]) + 1,
                                content.indexOf('\n', node.range[1])
                            ).trim();
                            
                            const days = delayValue / (1000 * 60 * 60 * 24);
                            
                            findings.push({
                                file: filePath,
                                type: "SUSPICIOUS_TIMER_DELAY",
                                timer_function: calleeName,
                                delay_ms: delayValue,
                                delay_days: days.toFixed(1),
                                severity: "MEDIUM",
                                reason: `Suspiciously long timer delay: ${days.toFixed(1)} days`,
                                snippet: line.substring(0, 100),
                                line: node.loc.start.line
                            });
                        }
                    }
                }
            }
            
            // Check for cron-like patterns or scheduled tasks
            if (node.type === 'CallExpression') {
                const calleeName = getCalleeName(node.callee);
                const cronKeywords = ['cron', 'schedule', 'timer', 'job', 'task'];
                
                if (cronKeywords.some(keyword => 
                    calleeName && calleeName.toLowerCase().includes(keyword))) {
                    
                    // Check for string patterns that look like cron expressions
                    for (const arg of node.arguments) {
                        if (arg.type === 'Literal' && typeof arg.value === 'string') {
                            const value = arg.value;
                            // Basic cron pattern detection
                            if (value.match(/^(\*|\d+|\d+-\d+|\d+\/\d+)(\s+(\*|\d+|\d+-\d+|\d+\/\d+)){4}$/)) {
                                const line = content.substring(
                                    content.lastIndexOf('\n', node.range[0]) + 1,
                                    content.indexOf('\n', node.range[1])
                                ).trim();
                                
                                findings.push({
                                    file: filePath,
                                    type: "CRON_SCHEDULE",
                                    cron_expression: value,
                                    severity: "MEDIUM",
                                    reason: `Cron-like scheduling pattern detected`,
                                    snippet: line.substring(0, 100),
                                    line: node.loc.start.line
                                });
                            }
                        }
                    }
                }
            }
            
            // Recursively traverse child nodes
            for (const key in node) {
                if (node[key] && typeof node[key] === 'object') {
                    if (Array.isArray(node[key])) {
                        node[key].forEach(child => traverse(child, depth + 1));
                    } else if (node[key].type) {
                        traverse(node[key], depth + 1);
                    }
                }
            }
        }
            
            traverse(ast);
        } catch (error) {
            // Skip files with parsing errors
            console.warn(`Failed to parse ${filePath}: ${error.message}`);
        }
    }
    
    // Helper function to get callee name
    function getCalleeName(node) {
        if (node.type === 'Identifier') {
            return node.name;
        } else if (node.type === 'MemberExpression') {
            return `${getCalleeName(node.object)}.${node.property.name || node.property.value}`;
        }
        return null;
    }
    
    // Helper function to check if node is a Date expression
    function isDateExpression(node) {
        // Date.now()
        if (node.type === 'CallExpression' &&
            node.callee.type === 'MemberExpression' &&
            node.callee.object.type === 'Identifier' &&
            node.callee.object.name === 'Date' &&
            node.callee.property.type === 'Identifier' &&
            node.callee.property.name === 'now') {
            return true;
        }
        
        // new Date().getTime()
        if (node.type === 'CallExpression' &&
            node.callee.type === 'MemberExpression' &&
            node.callee.property.type === 'Identifier' &&
            node.callee.property.name === 'getTime') {
            
            const obj = node.callee.object;
            if (obj.type === 'NewExpression' &&
                obj.callee.type === 'Identifier' &&
                obj.callee.name === 'Date') {
                return true;
            }
        }
        
        // new Date().valueOf()
        if (node.type === 'CallExpression' &&
            node.callee.type === 'MemberExpression' &&
            node.callee.property.type === 'Identifier' &&
            node.callee.property.name === 'valueOf') {
            
            const obj = node.callee.object;
            if (obj.type === 'NewExpression' &&
                obj.callee.type === 'Identifier' &&
                obj.callee.name === 'Date') {
                return true;
            }
        }
        
        return false;
    }
    
    // Helper function to extract numeric value from node
    function extractNumericValue(node) {
        if (node.type === 'Literal' && typeof node.value === 'number') {
            return node.value;
        }
        
        if (node.type === 'Literal' && typeof node.value === 'string') {
            // Try to parse as number
            const num = parseFloat(node.value);
            if (!isNaN(num)) return num;
            
            // Try to parse as date string
            const date = new Date(node.value);
            if (!isNaN(date.getTime())) return date.getTime();
        }
        
        if (node.type === 'UnaryExpression' && node.operator === '-') {
            const value = extractNumericValue(node.argument);
            return value !== null ? -value : null;
        }
        
        // Handle basic arithmetic for simple expressions
        if (node.type === 'BinaryExpression') {
            const left = extractNumericValue(node.left);
            const right = extractNumericValue(node.right);
            
            if (left !== null && right !== null) {
                switch (node.operator) {
                    case '+': return left + right;
                    case '-': return left - right;
                    case '*': return left * right;
                    case '/': return left / right;
                }
            }
        }
        
        return null;
    }
    
    // Also do simple regex scanning for time bomb patterns
    function regexScan(content, filePath) {
        // Pattern for explicit future date comparisons
        const futureDatePatterns = [
            // if (Date.now() > timestamp)
            /(?:if|while)\s*\(\s*(?:Date\.now\(\)|new\s+Date\(\)\.(?:getTime|valueOf)\(\))\s*[<>]=?\s*(\d{10,})\s*\)/g,
            
            // if (timestamp > Date.now())
            /(?:if|while)\s*\(\s*(\d{10,})\s*[<>]=?\s*(?:Date\.now\(\)|new\s+Date\(\)\.(?:getTime|valueOf)\(\))\s*\)/g,
            
            // Hardcoded date strings in comparisons
            /(?:if|while)\s*\(\s*(?:Date\.now\(\)|new\s+Date\(\)\.(?:getTime|valueOf)\(\))\s*[<>]=?\s*new\s+Date\(['"]([^'"]{8,})['"]\)/g,
            
            // setTimeout with very large delays
            /set(?:Timeout|Interval)\s*\(\s*(\d{8,})\s*,/g
        ];
        
        for (let i = 0; i < futureDatePatterns.length; i++) {
            const pattern = futureDatePatterns[i];
            let match;
            while ((match = pattern.exec(content)) !== null) {
                const value = match[1];
                const numericValue = parseInt(value, 10);
                
                if (!isNaN(numericValue) && numericValue > 1000000000000) { // Timestamp in milliseconds
                    const daysFuture = (numericValue - currentTimestamp) / (1000 * 60 * 60 * 24);
                    
                    if (daysFuture > FUTURE_THRESHOLD_DAYS) {
                        const lineStart = content.lastIndexOf('\n', match.index) + 1;
                        const lineEnd = content.indexOf('\n', match.index);
                        const line = content.substring(lineStart, lineEnd).trim();
                        
                        findings.push({
                            file: filePath,
                            type: "TIME_BOMB_PATTERN",
                            pattern_index: i,
                            matched_value: value,
                            days_from_now: daysFuture.toFixed(1),
                            severity: "HIGH",
                            reason: `Regex match for time bomb pattern (${daysFuture.toFixed(1)} days future)`,
                            snippet: line.substring(0, 100),
                            line: content.substring(0, match.index).split('\n').length
                        });
                    }
                }
            }
        }
    }
    
    // Analyze each file
    for (const file of files) {
        const content = file.content || "";
        const path = file.path.toLowerCase();
        
        // Skip non-JavaScript files unless specified
        if (path.endsWith('.js') || path.endsWith('.jsx') || 
            path.endsWith('.ts') || path.endsWith('.tsx') ||
            path.includes('package.json')) {
            
            // Use both AST and regex scanning for robustness
            analyzeCode(content, file.path);
            regexScan(content, file.path);
        }
    }
    
    // Determine overall risk
    let overallRisk = "LOW";
    const highSeverityCount = findings.filter(f => f.severity === "HIGH").length;
    const mediumSeverityCount = findings.filter(f => f.severity === "MEDIUM").length;
    
    if (highSeverityCount > 0) {
        overallRisk = "HIGH";
    } else if (mediumSeverityCount > 0) {
        overallRisk = "MEDIUM";
    }
    
    // Add summary if multiple findings
    if (findings.length > 1) {
        findings.unshift({
            file: "PACKAGE_OVERVIEW",
            type: "TIME_BOMB_SUMMARY",
            total_findings: findings.length,
            high_severity: highSeverityCount,
            medium_severity: mediumSeverityCount,
            severity: overallRisk,
            reason: `Multiple time bomb indicators detected (${findings.length} total)`,
            snippet: `Time bomb detection summary`
        });
    }
    
    return {
        rule: "rule13_time_bomb",
        description: "Detects time-based conditional logic for delayed malicious activation",
        findings,
        risk: overallRisk
    };
};