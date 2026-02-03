/**
 * Rule 12: Cryptocurrency Miner Detection
 * Detects cryptocurrency mining code, wallet addresses, and mining pool connections
 */

module.exports = function rule12_crypto_miner({ files }) {
    const findings = [];
    
    if (!Array.isArray(files)) {
        return {
            rule: "rule12_crypto_miner",
            description: "Detects cryptocurrency mining code and wallet addresses",
            findings: [],
            risk: "LOW"
        };
    }
    
    // Cryptocurrency wallet address patterns
    const walletPatterns = [
        // Bitcoin (P2PKH, P2SH, Bech32)
        { 
            name: "BITCOIN", 
            regex: /(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}/g,
            severity: "HIGH"
        },
        // Ethereum
        { 
            name: "ETHEREUM", 
            regex: /0x[a-fA-F0-9]{40}/g,
            severity: "HIGH"
        },
        // Litecoin
        { 
            name: "LITECOIN", 
            regex: /(L|M)[a-km-zA-HJ-NP-Z1-9]{26,34}/g,
            severity: "MEDIUM"
        },
        // Monero
        { 
            name: "MONERO", 
            regex: /4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}/g,
            severity: "MEDIUM"
        },
        // Dogecoin
        { 
            name: "DOGECOIN", 
            regex: /D{1}[5-9A-HJ-NP-U]{1}[1-9A-HJ-NP-Za-km-z]{32}/g,
            severity: "MEDIUM"
        },
        // Ripple
        { 
            name: "RIPPLE", 
            regex: /r[0-9a-zA-Z]{24,34}/g,
            severity: "MEDIUM"
        },
        // General crypto address (catch-all)
        { 
            name: "CRYPTO_ADDRESS", 
            regex: /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b|\b0x[a-fA-F0-9]{40}\b/g,
            severity: "MEDIUM"
        }
    ];
    
    // Mining-related keywords and patterns
    const miningPatterns = [
        // Mining library imports
        { 
            pattern: /require\s*\(\s*['"](coinhive|webcoin|coinimp|miner|coin-hive|cryptonight|mining)['"]/gi,
            name: "MINING_LIBRARY_IMPORT",
            severity: "HIGH"
        },
        { 
            pattern: /import\s+.*from\s+['"](coinhive|webcoin|coinimp|miner)['"]/gi,
            name: "MINING_LIBRARY_IMPORT",
            severity: "HIGH"
        },
        // Common mining pool domains
        { 
            pattern: /(pool\.minexmr\.com|stratum\.[^\s]+|nanopool\.org|nicehash\.com|miningpoolhub\.com)/gi,
            name: "MINING_POOL_CONNECTION",
            severity: "HIGH"
        },
        // Mining function names
        { 
            pattern: /\b(startMining|stopMining|mine|cpuMine|gpuMine|hashRate|minerConfig)\b/gi,
            name: "MINING_FUNCTION",
            severity: "MEDIUM"
        },
        // Cryptocurrency mining keywords
        { 
            pattern: /\b(cryptocurrency.?mining|bitcoin.?mining|eth.?mining|monero.?mining|mining.?rig|hash.?rate|proof.?of.?work)\b/gi,
            name: "MINING_KEYWORD",
            severity: "MEDIUM"
        },
        // Web mining scripts
        { 
            pattern: /new\s+Worker\s*\(\s*['"]miner\.js['"]|\.js\/miner\.js|miner\.start\(/gi,
            name: "WEB_MINER_SCRIPT",
            severity: "HIGH"
        },
        // CoinHive specific patterns (historical cryptojacking library)
        { 
            pattern: /\b(CoinHive|Authedmine|CryptoLoot|JSEcoin|DeepMiner)\b/gi,
            name: "KNOWN_MINER_LIBRARY",
            severity: "HIGH"
        },
        // Mining configuration
        { 
            pattern: /(threads|intensity|auto.?start|throttle|pool\.url|wallet|worker)/gi,
            name: "MINING_CONFIG",
            severity: "LOW",
            context: true  // Needs context verification
        }
    ];
    
    // Known mining scripts and libraries (partial content detection)
    const knownMinerFragments = [
        "CoinHive.User",
        "authedmine.com",
        "crypto-loot.com",
        "minero.cc",
        "miner.pr0gramm",
        "webassembly.instantiate",
        "cryptonight.wasm",
        "WebSocket.stratum"
    ];
    
    for (const file of files) {
        const content = file.content || "";
        const path = file.path.toLowerCase();
        
        // Skip package.json and README files for certain patterns
        const skipForBasicPatterns = path.includes('package.json') || path.includes('readme');
        
        // Check for wallet addresses
        for (const walletPattern of walletPatterns) {
            const matches = content.match(walletPattern.regex);
            if (matches) {
                const uniqueMatches = [...new Set(matches)].slice(0, 5); // Limit to 5 unique matches
                
                findings.push({
                    file: file.path,
                    type: "CRYPTO_WALLET",
                    crypto_type: walletPattern.name,
                    addresses: uniqueMatches,
                    count: matches.length,
                    severity: walletPattern.severity,
                    reason: `${walletPattern.name} wallet address detected in code`,
                    snippet: uniqueMatches[0] || "Unknown address"
                });
            }
        }
        
        // Check for mining patterns (skip for package.json/README unless it's library import)
        if (!skipForBasicPatterns || path.includes('.js')) {
            for (const miningPattern of miningPatterns) {
                const matches = content.match(miningPattern.pattern);
                if (matches) {
                    const uniqueMatches = [...new Set(matches)].slice(0, 3);
                    
                    // For context-based patterns, verify it's not just a comment or string
                    if (miningPattern.context) {
                        const lines = content.split('\n');
                        let foundInCode = false;
                        for (const line of lines) {
                            const trimmed = line.trim();
                            if (trimmed && !trimmed.startsWith('//') && !trimmed.startsWith('/*') && 
                                !trimmed.startsWith('*') && !trimmed.includes('http') &&
                                miningPattern.pattern.test(line)) {
                                foundInCode = true;
                                break;
                            }
                        }
                        if (!foundInCode) continue;
                    }
                    
                    findings.push({
                        file: file.path,
                        type: miningPattern.name,
                        matches: uniqueMatches,
                        count: matches.length,
                        severity: miningPattern.severity,
                        reason: `Cryptocurrency mining related code detected: ${miningPattern.name}`,
                        snippet: uniqueMatches[0] || "Unknown pattern"
                    });
                }
            }
        }
        
        // Check for known miner fragments
        for (const fragment of knownMinerFragments) {
            if (content.includes(fragment)) {
                const lines = content.split('\n');
                const contextLine = lines.find(line => line.includes(fragment)) || "";
                
                findings.push({
                    file: file.path,
                    type: "KNOWN_MINER_FRAGMENT",
                    fragment: fragment,
                    severity: "HIGH",
                    reason: `Known cryptominer code fragment detected: ${fragment}`,
                    snippet: contextLine.substring(0, 100) + (contextLine.length > 100 ? "..." : "")
                });
            }
        }
        
        // Check for suspicious WebSocket connections to mining pools
        const wsPattern = /new\s+WebSocket\s*\(\s*['"](wss?:\/\/[^'"]*(?:pool|mine|stratum|mining)[^'"]*)['"]/gi;
        const wsMatches = content.match(wsPattern);
        if (wsMatches) {
            findings.push({
                file: file.path,
                type: "MINING_WEBSOCKET",
                endpoints: [...new Set(wsMatches)].slice(0, 3),
                severity: "HIGH",
                reason: "WebSocket connection to potential mining pool detected",
                snippet: wsMatches[0] || "Unknown endpoint"
            });
        }
        
        // Check for WASM mining modules
        const wasmPattern = /WebAssembly\.(instantiate|compile)\s*\(|\.wasm['"]/gi;
        const wasmMatches = content.match(wasmPattern);
        if (wasmMatches && content.includes('cryptonight') || content.includes('mining')) {
            findings.push({
                file: file.path,
                type: "WASM_MINER",
                wasm_usage: true,
                severity: "HIGH",
                reason: "WebAssembly usage with mining keywords detected",
                snippet: "WASM module with mining context"
            });
        }
    }
    
    // Aggregate findings by severity
    const highSeverityCount = findings.filter(f => f.severity === "HIGH").length;
    const mediumSeverityCount = findings.filter(f => f.severity === "MEDIUM").length;
    
    // Add summary finding if multiple detections
    if (findings.length >= 3) {
        findings.unshift({
            file: "PACKAGE_OVERVIEW",
            type: "CRYPTOMINER_SUMMARY",
            total_findings: findings.length,
            high_severity: highSeverityCount,
            medium_severity: mediumSeverityCount,
            severity: highSeverityCount > 0 ? "HIGH" : mediumSeverityCount > 0 ? "MEDIUM" : "LOW",
            reason: `Multiple cryptominer indicators detected (${findings.length} total findings)`,
            snippet: `Cryptominer detection: ${highSeverityCount} HIGH, ${mediumSeverityCount} MEDIUM`
        });
    }
    
    // Determine overall risk
    let overallRisk = "LOW";
    if (highSeverityCount > 0) {
        overallRisk = "HIGH";
    } else if (mediumSeverityCount > 0) {
        overallRisk = "MEDIUM";
    } else if (findings.length > 0) {
        overallRisk = "LOW";
    }
    
    return {
        rule: "rule12_crypto_miner",
        description: "Detects cryptocurrency mining code and wallet addresses",
        findings,
        risk: overallRisk
    };
};