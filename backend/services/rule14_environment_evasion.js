/**
 * Rule 14: Environment-Based Evasion Detection
 * Detects code that checks for sandbox/analysis environments and behaves differently
 */

module.exports = function rule14_env_evasion({ files }) {
    const findings = [];
    
    if (!Array.isArray(files)) {
        return {
            rule: "rule14_env_evasion",
            description: "Detects environment checks for sandbox/analysis evasion",
            findings: [],
            risk: "LOW"
        };
    }
    
    // Environment variables commonly checked for evasion
    const envVarPatterns = [
        // Sandbox/VM detection
        { pattern: /process\.env\.(VIRTUAL|VMWARE|VBOX|QEMU|XEN|HYPERV|PARALLELS)/i, type: "VM_ENV_VAR", severity: "HIGH" },
        { pattern: /process\.env\.(SANDBOX|DEBUGGER|ANALYSIS|DETECT)/i, type: "ANALYSIS_ENV_VAR", severity: "HIGH" },
        
        // CI/CD and testing environments
        { pattern: /process\.env\.(CI|CONTINUOUS_INTEGRATION|TEST|NODE_ENV\s*!==?\s*['"]production['"])/i, type: "CI_ENV_CHECK", severity: "MEDIUM" },
        { pattern: /process\.env\.(JEST|MOCHA|JASMINE|KARMA|AVA|TAPE)/i, type: "TEST_FRAMEWORK_ENV", severity: "MEDIUM" },
        
        // Debugging tools
        { pattern: /process\.env\.(DEBUG|NODE_DEBUG|INSPECTOR|DEVTOOLS)/i, type: "DEBUG_ENV_VAR", severity: "MEDIUM" },
        
        // Container/cloud environments
        { pattern: /process\.env\.(DOCKER|KUBERNETES|AWS|AZURE|GCP|CLOUD)/i, type: "CONTAINER_ENV_VAR", severity: "LOW" },
        
        // User/process related
        { pattern: /process\.env\.(USER|USERNAME|HOME|HOSTNAME)\s*(===|!==|==|!=)\s*['"][^'"]*['"]/i, type: "USER_ENV_CHECK", severity: "MEDIUM" },
        
        // Timing/performance checks for sandboxes
        { pattern: /process\.env\.(PERFORMANCE|TIMING|SPEED)/i, type: "PERFORMANCE_ENV_CHECK", severity: "MEDIUM" }
    ];
    
    // File system checks for VM/sandbox detection
    const fsCheckPatterns = [
        // VM-specific files and directories
        { pattern: /fs\.(existsSync|readFileSync|statSync)\(['"](\\?\/proc\\?\/|\\?\/sys\\?\/)/, type: "LINUX_VM_FILE_CHECK", severity: "HIGH" },
        { pattern: /fs\.(existsSync|readFileSync|statSync)\(['"](C:\\\\Windows\\\\System32\\\\drivers\\\\vmmouse|C:\\\\Program Files\\\\VMware)/i, type: "WINDOWS_VM_FILE_CHECK", severity: "HIGH" },
        { pattern: /fs\.(existsSync|readFileSync|statSync)\(['"](\\?\/dev\\?\/vmnet|\\?\/Library\\?\/Preferences\\?\/VMware)/i, type: "MAC_VM_FILE_CHECK", severity: "HIGH" },
        
        // Debugger/analysis tool files
        { pattern: /fs\.(existsSync|readFileSync|statSync)\(['"](\\?\/.*(debugger|gdb|windbg|ida|ollydbg|x64dbg|wireshark|fiddler))/, type: "DEBUGGER_FILE_CHECK", severity: "HIGH" },
        
        // Sandbox-specific artifacts
        { pattern: /fs\.(existsSync|readFileSync|statSync)\(['"](\\?\/tmp\\?\/sandbox|\\?\/var\\?\/run\\?\/sandbox)/i, type: "SANDBOX_FILE_CHECK", severity: "HIGH" }
    ];
    
    // Network/connection checks for analysis environments
    const networkCheckPatterns = [
        // Checking for internet connectivity
        { pattern: /fetch\(['"]https?:\/\/checkip\.|['"]http:\/\/icanhazip\./, type: "INTERNET_CONNECTIVITY_CHECK", severity: "MEDIUM" },
        
        // Checking for specific network interfaces
        { pattern: /require\('os'\)\.networkInterfaces\(\)|networkInterfaces\(\)\.(filter|find|some)/, type: "NETWORK_INTERFACE_CHECK", severity: "MEDIUM" },
        
        // DNS checks for VM/sandbox
        { pattern: /dns\.(resolve|lookup)\(['"](vmware|virtualbox|qemu|microsoft|parallels)/i, type: "DNS_VM_CHECK", severity: "HIGH" }
    ];
    
    // Process/performance checks
    const processCheckPatterns = [
        // Checking process count or names
        { pattern: /require\('child_process'\)\.exec(?:Sync)?\(['"]ps aux|tasklist|wmic/, type: "PROCESS_LIST_CHECK", severity: "HIGH" },
        
        // Checking CPU/memory (sandboxes often have limited resources)
        { pattern: /require\('os'\)\.cpus\(\)\.length\s*(<|<=)\s*\d+/, type: "CPU_COUNT_CHECK", severity: "MEDIUM" },
        { pattern: /require\('os'\)\.totalmem\(\)\s*(<|<=)\s*\d+/, type: "MEMORY_CHECK", severity: "MEDIUM" },
        
        // Checking uptime (sandboxes often have short uptime)
        { pattern: /require\('os'\)\.uptime\(\)\s*(<|<=)\s*\d+/, type: "UPTIME_CHECK", severity: "MEDIUM" },
        
        // Checking for parent processes (debuggers, analysis tools)
        { pattern: /process\.ppid|process\.parent|process\.execArgv\.includes\('--inspect'\)/, type: "PARENT_PROCESS_CHECK", severity: "HIGH" }
    ];
    
    // Browser/headless environment checks
    const browserCheckPatterns = [
        // Checking for headless browsers
        { pattern: /navigator\.(plugins|mimeTypes)\.length\s*(===|==|!==|!=)\s*0/, type: "HEADLESS_BROWSER_CHECK", severity: "HIGH" },
        { pattern: /navigator\.webdriver\s*(===|==)\s*true/, type: "WEBDRIVER_CHECK", severity: "HIGH" },
        { pattern: /window\.(outerWidth|outerHeight|screenX|screenY)\s*(===|==)\s*0/, type: "WINDOW_SIZE_CHECK", severity: "MEDIUM" },
        { pattern: /'HeadlessChrome'\.test\(navigator\.userAgent\)/, type: "USER_AGENT_CHECK", severity: "HIGH" },
        
        // Checking for devtools
        { pattern: /console\.(debug|trace|time|profile)/, type: "CONSOLE_METHOD_CHECK", severity: "LOW", context: true },
        { pattern: /devtools\s*(===|==)\s*true|\.open\(\)/, type: "DEVTOOLS_CHECK", severity: "MEDIUM" }
    ];
    
    // Common evasion code patterns (conditional blocks)
    const evasionPatterns = [
        // Early returns when in analysis environment
        { pattern: /if\s*\(\s*(?:process\.env\.[A-Z_]+\s*(===|!==|==|!=)\s*['"][^'"]*['"]|fs\.existsSync\([^)]+\))\s*\)\s*{\s*return[^}]*}/s, type: "EARLY_RETURN_EVASION", severity: "HIGH" },
        
        // Behavior switching based on environment
        { pattern: /if\s*\(\s*(?:process\.env\.[A-Z_]+|navigator\.[a-zA-Z]+|fs\.existsSync)\s*\).*?{\s*[^}]*malicious|payload|exploit|steal[^}]*}/is, type: "BEHAVIOR_SWITCH_EVASION", severity: "HIGH" },
        
        // Delayed execution or timeout when detected
        { pattern: /if\s*\(\s*(?:process\.env\.[A-Z_]+|fs\.existsSync)\s*\).*?setTimeout\([^,]+,\s*\d+\)/s, type: "DELAYED_EVASION", severity: "MEDIUM" },
        
        // Different code paths for different environments
        { pattern: /process\.env\.[A-Z_]+\s*\?\s*\([^)]*\)\s*:\s*\([^)]*\)/, type: "TERNARY_EVASION", severity: "MEDIUM" }
    ];
    
    // Suspicious functions that often contain evasion logic
    const suspiciousFunctions = [
        'isSandboxed', 'isVM', 'isDebuggerPresent', 'isAnalysisEnvironment',
        'checkEnvironment', 'detectVM', 'avoidDetection', 'evadeSandbox'
    ];
    
    function analyzeFile(content, filePath) {
        const lines = content.split('\n');
        
        // Check for suspicious function names
        for (const funcName of suspiciousFunctions) {
            const funcPattern = new RegExp(`function\\s+${funcName}|const\\s+${funcName}\\s*=|let\\s+${funcName}\\s*=|var\\s+${funcName}\\s*=`, 'i');
            if (funcPattern.test(content)) {
                const lineIndex = lines.findIndex(line => funcPattern.test(line));
                findings.push({
                    file: filePath,
                    type: "SUSPICIOUS_FUNCTION_NAME",
                    function_name: funcName,
                    severity: "HIGH",
                    reason: `Function named '${funcName}' suggests environment detection logic`,
                    snippet: lineIndex >= 0 ? lines[lineIndex].trim() : "Function definition",
                    line: lineIndex + 1
                });
            }
        }
        
        // Analyze each pattern category
        const allPatterns = [
            ...envVarPatterns,
            ...fsCheckPatterns,
            ...networkCheckPatterns,
            ...processCheckPatterns,
            ...browserCheckPatterns,
            ...evasionPatterns
        ];
        
        for (let i = 0; i < allPatterns.length; i++) {
            const patternObj = allPatterns[i];
            const regex = new RegExp(patternObj.pattern.source || patternObj.pattern, patternObj.pattern.flags || 'g');
            let match;
            
            while ((match = regex.exec(content)) !== null) {
                // For context-sensitive patterns, verify it's not just a comment
                if (patternObj.context) {
                    const lineStart = content.lastIndexOf('\n', match.index) + 1;
                    const line = content.substring(lineStart, content.indexOf('\n', match.index)).trim();
                    
                    if (line.startsWith('//') || line.startsWith('/*') || line.startsWith('*')) {
                        continue; // Skip comments
                    }
                }
                
                // Extract context around the match
                const lineStart = content.lastIndexOf('\n', match.index) + 1;
                const lineEnd = content.indexOf('\n', match.index);
                const line = content.substring(lineStart, lineEnd >= 0 ? lineEnd : content.length).trim();
                
                // Check if this is part of a conditional statement
                const contextStart = Math.max(0, match.index - 100);
                const contextEnd = Math.min(content.length, match.index + 100);
                const context = content.substring(contextStart, contextEnd);
                
                const isInConditional = /if\s*\(|else|switch\s*\(|case\s+/.test(context);
                const hasEarlyReturn = /return\s+|throw\s+|process\.exit\(/.test(context);
                const hasBehaviorSwitch = /malicious|payload|exploit|steal|backdoor|miner|keylogger/i.test(context);
                
                let reason = patternObj.type.replace(/_/g, ' ').toLowerCase();
                if (isInConditional) reason += " in conditional statement";
                if (hasEarlyReturn) reason += " with early return";
                if (hasBehaviorSwitch) reason += " with behavior switching";
                
                findings.push({
                    file: filePath,
                    type: patternObj.type,
                    matched_pattern: match[0].substring(0, 100),
                    severity: patternObj.severity,
                    conditional: isInConditional,
                    early_return: hasEarlyReturn,
                    behavior_switch: hasBehaviorSwitch,
                    reason: reason,
                    snippet: line.substring(0, 150),
                    line: content.substring(0, match.index).split('\n').length
                });
                
                // For evasion patterns, also check the surrounding code block
                if (patternObj.type.includes('EVASION') && isInConditional) {
                    // Try to find the end of the conditional block
                    let braceCount = 0;
                    let inBlock = false;
                    let blockEnd = match.index;
                    
                    for (let j = match.index; j < Math.min(content.length, match.index + 1000); j++) {
                        if (content[j] === '{') {
                            braceCount++;
                            inBlock = true;
                        } else if (content[j] === '}') {
                            braceCount--;
                            if (inBlock && braceCount === 0) {
                                blockEnd = j;
                                break;
                            }
                        }
                    }
                    
                    if (blockEnd > match.index) {
                        const blockContent = content.substring(match.index, blockEnd + 1);
                        
                        // Check for suspicious content in the block
                        const suspiciousInBlock = /(?:steal|exfiltrate|malware|payload|backdoor|exploit|miner|keylogger|rat|spyware)/i.test(blockContent);
                        const benignInBlock = /(?:log|console|debug|test|mock|stub)/i.test(blockContent);
                        
                        if (suspiciousInBlock && !benignInBlock) {
                            findings.push({
                                file: filePath,
                                type: "EVASION_WITH_MALICIOUS_BLOCK",
                                severity: "HIGH",
                                reason: "Environment check followed by suspicious code block",
                                snippet: blockContent.substring(0, 200) + (blockContent.length > 200 ? "..." : ""),
                                line: content.substring(0, match.index).split('\n').length
                            });
                        }
                    }
                }
            }
        }
        
        // Check for multi-line evasion patterns
        const multiLineEvasionPatterns = [
            // Check for environment detection then different behavior
            /if\s*\([^)]*(?:process\.env|fs\.exists|navigator\.|window\.)[^)]*\)\s*{[^}]*}(?:\s*else\s*{[^}]*})?/g
        ];
        
        for (const pattern of multiLineEvasionPatterns) {
            let match;
            while ((match = pattern.exec(content)) !== null) {
                const block = match[0];
                
                // Check if this is likely evasion (has suspicious content in one branch)
                const hasSuspiciousTerms = /(?:steal|malware|payload|exploit|backdoor|miner|keylogger)/i.test(block);
                const hasEnvCheck = /process\.env|fs\.exists|navigator\.|window\./.test(block);
                
                if (hasEnvCheck && hasSuspiciousTerms) {
                    const lineStart = content.lastIndexOf('\n', match.index) + 1;
                    const line = content.substring(lineStart, content.indexOf('\n', match.index)).trim();
                    
                    findings.push({
                        file: filePath,
                        type: "MULTI_LINE_EVASION",
                        severity: "HIGH",
                        reason: "Multi-line environment check with suspicious behavior switching",
                        snippet: line.substring(0, 100) + "...",
                        line: content.substring(0, match.index).split('\n').length,
                        block_preview: block.substring(0, 200) + (block.length > 200 ? "..." : "")
                    });
                }
            }
        }
    }
    
    // Analyze each file
    for (const file of files) {
        const content = file.content || "";
        const path = file.path.toLowerCase();
        
        // Analyze JavaScript/TypeScript files
        if (path.endsWith('.js') || path.endsWith('.jsx') || 
            path.endsWith('.ts') || path.endsWith('.tsx')) {
            analyzeFile(content, file.path);
        }
        
        // Also check package.json for suspicious scripts
        if (path.endsWith('package.json')) {
            try {
                const pkg = JSON.parse(content);
                if (pkg.scripts) {
                    for (const [scriptName, scriptContent] of Object.entries(pkg.scripts)) {
                        if (typeof scriptContent === 'string') {
                            // Check for environment-based script execution
                            if (scriptContent.includes('NODE_ENV') || 
                                scriptContent.includes('process.env') ||
                                scriptContent.includes('cross-env')) {
                                
                                findings.push({
                                    file: file.path,
                                    type: "ENV_BASED_SCRIPT",
                                    script_name: scriptName,
                                    severity: "LOW",
                                    reason: "Package script uses environment variables for conditional execution",
                                    snippet: scriptContent.substring(0, 100)
                                });
                            }
                        }
                    }
                }
            } catch (e) {
                // Skip invalid JSON
            }
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
            type: "ENV_EVASION_SUMMARY",
            total_findings: findings.length,
            high_severity: highSeverityCount,
            medium_severity: mediumSeverityCount,
            severity: overallRisk,
            reason: `Multiple environment evasion indicators detected`,
            snippet: `Environment evasion detection: ${highSeverityCount} HIGH, ${mediumSeverityCount} MEDIUM findings`
        });
    }
    
    return {
        rule: "rule14_env_evasion",
        description: "Detects environment checks for sandbox/analysis evasion",
        findings,
        risk: overallRisk
    };
};