/**
 * Rule 15: Unicode/Homoglyph Obfuscation Detection
 * Detects use of visually similar Unicode characters to hide malicious identifiers
 */

module.exports = function rule15_unicode_obfuscation({ files }) {
    const findings = [];
    
    if (!Array.isArray(files)) {
        return {
            rule: "rule15_unicode_obfuscation",
            description: "Detects Unicode homoglyph obfuscation in identifiers",
            findings: [],
            risk: "LOW"
        };
    }
    
    // Common homoglyph substitutions for dangerous identifiers
    const homoglyphTargets = [
        // eval variations (е = Cyrillic ye, ё = Cyrillic yo)
        { original: "eval", unicode: ["еval", "еvаl", "evаl", "ёval", "еvаl"], severity: "HIGH" },
        
        // require variations
        { original: "require", unicode: ["rеquirе", "rеquіrе", "requirе", "геԛuire"], severity: "HIGH" },
        
        // process variations
        { original: "process", unicode: ["рrocess", "procеss", "proсеss", "рrосеss"], severity: "HIGH" },
        
        // child_process variations
        { original: "child_process", unicode: ["child_рrocess", "сhild_process", "child_procеss"], severity: "HIGH" },
        
        // fs variations
        { original: "fs", unicode: ["fѕ", "fѕ", "f𝘀"], severity: "MEDIUM" },
        
        // exec variations
        { original: "exec", unicode: ["еxес", "exес", "exеc", "ехес"], severity: "HIGH" },
        
        // spawn variations
        { original: "spawn", unicode: ["ѕраwn", "spаwn", "spawn", "ѕраwп"], severity: "HIGH" },
        
        // fetch variations
        { original: "fetch", unicode: ["fеtсh", "fetсh", "fetcһ"], severity: "MEDIUM" },
        
        // document variations
        { original: "document", unicode: ["dосument", "doсument", "documеnt", "dосumеnt"], severity: "MEDIUM" },
        
        // window variations
        { original: "window", unicode: ["wіndow", "windоw", "wіndоw"], severity: "MEDIUM" },
        
        // alert variations
        { original: "alert", unicode: ["аlert", "alеrt", "аlеrt"], severity: "MEDIUM" },
        
        // console variations
        { original: "console", unicode: ["сonsole", "consolе", "сonsolе"], severity: "LOW" },
        
        // Dangerous function names often obfuscated
        { original: "constructor", unicode: ["сonstructor", "constructоr", "conѕtructor"], severity: "MEDIUM" },
        { original: "prototype", unicode: ["рrototype", "prototуpe", "prоtоtype"], severity: "MEDIUM" },
        { original: "toString", unicode: ["tоString", "toStrіng", "tоStrіng"], severity: "MEDIUM" }
    ];
    
    // Zero-width and invisible Unicode characters
    const invisibleChars = [
        { code: "U+200B", char: "\u200B", name: "ZERO WIDTH SPACE", severity: "HIGH" },
        { code: "U+200C", char: "\u200C", name: "ZERO WIDTH NON-JOINER", severity: "HIGH" },
        { code: "U+200D", char: "\u200D", name: "ZERO WIDTH JOINER", severity: "HIGH" },
        { code: "U+200E", char: "\u200E", name: "LEFT-TO-RIGHT MARK", severity: "MEDIUM" },
        { code: "U+200F", char: "\u200F", name: "RIGHT-TO-LEFT MARK", severity: "HIGH" },
        { code: "U+202A", char: "\u202A", name: "LEFT-TO-RIGHT EMBEDDING", severity: "MEDIUM" },
        { code: "U+202B", char: "\u202B", name: "RIGHT-TO-LEFT EMBEDDING", severity: "HIGH" },
        { code: "U+202C", char: "\u202C", name: "POP DIRECTIONAL FORMATTING", severity: "MEDIUM" },
        { code: "U+202D", char: "\u202D", name: "LEFT-TO-RIGHT OVERRIDE", severity: "HIGH" },
        { code: "U+202E", char: "\u202E", name: "RIGHT-TO-LEFT OVERRIDE", severity: "HIGH" },
        { code: "U+FEFF", char: "\uFEFF", name: "ZERO WIDTH NO-BREAK SPACE", severity: "HIGH" },
        { code: "U+2060", char: "\u2060", name: "WORD JOINER", severity: "MEDIUM" },
        { code: "U+2061", char: "\u2061", name: "FUNCTION APPLICATION", severity: "LOW" },
        { code: "U+2062", char: "\u2062", name: "INVISIBLE TIMES", severity: "LOW" },
        { code: "U+2063", char: "\u2063", name: "INVISIBLE SEPARATOR", severity: "MEDIUM" }
    ];
    
    // Mixed script detection - characters from different Unicode blocks
    const scriptBlocks = {
        'latin': /[\u0041-\u007A\u00C0-\u00FF]/,
        'cyrillic': /[\u0400-\u04FF\u0500-\u052F]/,
        'greek': /[\u0370-\u03FF\u1F00-\u1FFF]/,
        'armenian': /[\u0530-\u058F]/,
        'hebrew': /[\u0590-\u05FF]/,
        'arabic': /[\u0600-\u06FF\u0750-\u077F]/,
        'devanagari': /[\u0900-\u097F]/,
        'bengali': /[\u0980-\u09FF]/,
        'cjk': /[\u4E00-\u9FFF\u3400-\u4DBF\uF900-\uFAFF]/,
        'hangul': /[\uAC00-\uD7AF\u1100-\u11FF]/
    };
    
    // Common dangerous APIs that attackers try to obfuscate
    const dangerousAPIs = [
        'eval', 'Function', 'setTimeout', 'setInterval', 'exec', 'spawn', 'execSync', 'spawnSync',
        'require', 'import', 'process', 'child_process', 'fs', 'os', 'net', 'http', 'https',
        'document.write', 'innerHTML', 'outerHTML', 'insertAdjacentHTML', 'createElement',
        'setAttribute', 'addEventListener', 'removeEventListener', 'XMLHttpRequest', 'fetch',
        'WebSocket', 'localStorage', 'sessionStorage', 'cookie', 'IndexedDB', 'FileReader',
        'Blob', 'URL.createObjectURL', 'postMessage', 'importScripts', 'Worker'
    ];
    
    function containsInvisibleChars(text) {
        for (const invisible of invisibleChars) {
            if (text.includes(invisible.char)) {
                return {
                    found: true,
                    char: invisible.char,
                    name: invisible.name,
                    code: invisible.code,
                    severity: invisible.severity
                };
            }
        }
        return { found: false };
    }
    
    function detectMixedScript(text) {
        const scripts = new Set();
        for (const [scriptName, regex] of Object.entries(scriptBlocks)) {
            if (regex.test(text)) {
                scripts.add(scriptName);
            }
        }
        return scripts.size > 1 ? Array.from(scripts) : null;
    }
    
    function findHomoglyphs(text) {
        const findings = [];
        
        // Check for homoglyph substitutions in identifiers
        for (const target of homoglyphTargets) {
            for (const unicodeVariant of target.unicode) {
                // Look for the unicode variant in the text
                const regex = new RegExp(`\\b${unicodeVariant.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'gi');
                const matches = text.match(regex);
                
                if (matches) {
                    findings.push({
                        original: target.original,
                        obfuscated: matches[0],
                        severity: target.severity,
                        type: "HOMOGLYPH_SUBSTITUTION"
                    });
                }
            }
        }
        
        return findings;
    }
    
    function analyzeJavaScriptContent(content, filePath) {
        const lines = content.split('\n');
        
        // Extract identifiers (function names, variable names, property names)
        const identifierPattern = /(?:\b(?:const|let|var|function|class)\s+|\b)([a-zA-Z_$][\w$]*)/g;
        const propertyPattern = /\.([a-zA-Z_$][\w$]*)\s*(?:\(|=|:|;)/g;
        const stringPattern = /(['"`])(.*?)\1/g;
        
        // Track all identifiers found
        const allIdentifiers = new Set();
        
        // First pass: collect all identifiers
        let match;
        while ((match = identifierPattern.exec(content)) !== null) {
            allIdentifiers.add(match[1]);
        }
        
        while ((match = propertyPattern.exec(content)) !== null) {
            allIdentifiers.add(match[1]);
        }
        
        // Analyze each identifier
        for (const identifier of allIdentifiers) {
            // Skip very short identifiers
            if (identifier.length < 2) continue;
            
            // Check for invisible characters
            const invisibleCheck = containsInvisibleChars(identifier);
            if (invisibleCheck.found) {
                const lineIndex = findLineContainingIdentifier(content, identifier);
                findings.push({
                    file: filePath,
                    type: "INVISIBLE_CHAR_IN_IDENTIFIER",
                    identifier: identifier,
                    invisible_char: invisibleCheck.char,
                    char_name: invisibleCheck.name,
                    char_code: invisibleCheck.code,
                    severity: invisibleCheck.severity,
                    reason: `Identifier contains invisible Unicode character: ${invisibleCheck.name}`,
                    snippet: lineIndex >= 0 ? lines[lineIndex].trim() : identifier,
                    line: lineIndex + 1,
                    escaped_identifier: escapeUnicode(identifier)
                });
            }
            
            // Check for mixed scripts
            const mixedScripts = detectMixedScript(identifier);
            if (mixedScripts) {
                const lineIndex = findLineContainingIdentifier(content, identifier);
                findings.push({
                    file: filePath,
                    type: "MIXED_SCRIPT_IDENTIFIER",
                    identifier: identifier,
                    scripts: mixedScripts,
                    severity: "HIGH",
                    reason: `Identifier uses mixed Unicode scripts: ${mixedScripts.join(', ')}`,
                    snippet: lineIndex >= 0 ? lines[lineIndex].trim() : identifier,
                    line: lineIndex + 1,
                    escaped_identifier: escapeUnicode(identifier)
                });
            }
            
            // Check for homoglyph substitutions
            const homoglyphFindings = findHomoglyphs(identifier);
            for (const finding of homoglyphFindings) {
                const lineIndex = findLineContainingIdentifier(content, identifier);
                findings.push({
                    file: filePath,
                    type: finding.type,
                    original_identifier: finding.original,
                    obfuscated_identifier: finding.obfuscated,
                    severity: finding.severity,
                    reason: `Homoglyph substitution detected: ${finding.original} → ${finding.obfuscated}`,
                    snippet: lineIndex >= 0 ? lines[lineIndex].trim() : identifier,
                    line: lineIndex + 1,
                    escaped_identifier: escapeUnicode(identifier),
                    visual_similarity: "HIGH"
                });
            }
            
            // Check if identifier looks like dangerous API but with obfuscation
            for (const dangerousAPI of dangerousAPIs) {
                if (identifier.toLowerCase() === dangerousAPI.toLowerCase() && identifier !== dangerousAPI) {
                    // Case variation might be obfuscation
                    const lineIndex = findLineContainingIdentifier(content, identifier);
                    findings.push({
                        file: filePath,
                        type: "CASE_OBFUSCATED_API",
                        original_api: dangerousAPI,
                        obfuscated_version: identifier,
                        severity: "MEDIUM",
                        reason: `Dangerous API name with case obfuscation: ${dangerousAPI} → ${identifier}`,
                        snippet: lineIndex >= 0 ? lines[lineIndex].trim() : identifier,
                        line: lineIndex + 1,
                        escaped_identifier: escapeUnicode(identifier)
                    });
                }
            }
        }
        
        // Check strings for homoglyphs and invisible chars
        let stringMatch;
        while ((stringMatch = stringPattern.exec(content)) !== null) {
            const stringContent = stringMatch[2];
            
            // Check for invisible characters in strings
            const invisibleInString = containsInvisibleChars(stringContent);
            if (invisibleInString.found && stringContent.length > 5) {
                const lineIndex = content.substring(0, stringMatch.index).split('\n').length - 1;
                findings.push({
                    file: filePath,
                    type: "INVISIBLE_CHAR_IN_STRING",
                    string_preview: stringContent.substring(0, 50),
                    invisible_char: invisibleInString.char,
                    char_name: invisibleInString.name,
                    char_code: invisibleInString.code,
                    severity: invisibleInString.severity,
                    reason: `String contains invisible Unicode character: ${invisibleInString.name}`,
                    snippet: lines[lineIndex].trim(),
                    line: lineIndex + 1,
                    escaped_string: escapeUnicode(stringContent.substring(0, 100))
                });
            }
            
            // Check for homoglyphs in strings that look like code
            const homoglyphInString = findHomoglyphs(stringContent);
            for (const finding of homoglyphInString) {
                const lineIndex = content.substring(0, stringMatch.index).split('\n').length - 1;
                findings.push({
                    file: filePath,
                    type: "HOMOGLYPH_IN_STRING",
                    original: finding.original,
                    obfuscated: finding.obfuscated,
                    severity: finding.severity,
                    reason: `String contains homoglyph-obfuscated identifier: ${finding.original}`,
                    snippet: lines[lineIndex].trim(),
                    line: lineIndex + 1,
                    escaped_string: escapeUnicode(stringContent.substring(0, 100))
                });
            }
        }
        
        // Check for RTL/LTR override sequences
        const rtlPattern = /[\u200E-\u200F\u202A-\u202E]/g;
        const rtlMatches = content.match(rtlPattern);
        if (rtlMatches) {
            const uniqueRTL = [...new Set(rtlMatches)];
            const lineIndex = findFirstLineWithPattern(content, rtlPattern);
            
            findings.push({
                file: filePath,
                type: "DIRECTIONAL_FORMATTING_CHARS",
                characters: uniqueRTL,
                count: rtlMatches.length,
                severity: "HIGH",
                reason: "Text contains directional formatting characters that can reorder content",
                snippet: lineIndex >= 0 ? lines[lineIndex].trim() : "Directional characters found",
                line: lineIndex + 1
            });
        }
        
        // Check for zero-width characters near dangerous patterns
        const dangerousPattern = /(?:eval|Function|exec|spawn|require)\(/g;
        let dangerousMatch;
        while ((dangerousMatch = dangerousPattern.exec(content)) !== null) {
            // Check 20 characters before and after for zero-width chars
            const start = Math.max(0, dangerousMatch.index - 20);
            const end = Math.min(content.length, dangerousMatch.index + dangerousMatch[0].length + 20);
            const context = content.substring(start, end);
            
            const zwMatches = context.match(/[\u200B-\u200D\u2060-\u2063]/g);
            if (zwMatches) {
                const lineIndex = content.substring(0, dangerousMatch.index).split('\n').length - 1;
                
                findings.push({
                    file: filePath,
                    type: "ZERO_WIDTH_NEAR_DANGEROUS_CODE",
                    dangerous_pattern: dangerousMatch[0],
                    zero_width_chars: [...new Set(zwMatches)],
                    severity: "HIGH",
                    reason: "Zero-width characters found near dangerous API call",
                    snippet: lines[lineIndex].trim(),
                    line: lineIndex + 1,
                    context: context
                });
            }
        }
    }
    
    function findLineContainingIdentifier(content, identifier) {
        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
            // Use regex to find whole word match
            const regex = new RegExp(`\\b${identifier.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`);
            if (regex.test(lines[i])) {
                return i;
            }
        }
        return -1;
    }
    
    function findFirstLineWithPattern(content, pattern) {
        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
            if (pattern.test(lines[i])) {
                return i;
            }
        }
        return -1;
    }
    
    function escapeUnicode(str) {
        return str.replace(/[\u007F-\uFFFF]/g, (ch) => {
            return "\\u" + ("0000" + ch.charCodeAt(0).toString(16)).slice(-4);
        });
    }
    
    // Analyze each file
    for (const file of files) {
        const content = file.content || "";
        const path = file.path.toLowerCase();
        
        // Analyze JavaScript/TypeScript files
        if (path.endsWith('.js') || path.endsWith('.jsx') || 
            path.endsWith('.ts') || path.endsWith('.tsx')) {
            analyzeJavaScriptContent(content, file.path);
        }
        
        // Also check JSON files (package.json might contain obfuscated strings)
        if (path.endsWith('.json') || path.endsWith('.json5')) {
            try {
                // Check for invisible chars in JSON
                const invisibleCheck = containsInvisibleChars(content);
                if (invisibleCheck.found) {
                    findings.push({
                        file: file.path,
                        type: "INVISIBLE_CHAR_IN_JSON",
                        invisible_char: invisibleCheck.char,
                        char_name: invisibleCheck.name,
                        char_code: invisibleCheck.code,
                        severity: invisibleCheck.severity,
                        reason: `JSON file contains invisible Unicode character: ${invisibleCheck.name}`,
                        snippet: content.substring(0, 100),
                        escaped_content: escapeUnicode(content.substring(0, 200))
                    });
                }
            } catch (e) {
                // Skip invalid JSON
            }
        }
        
        // Check HTML files for obfuscated script tags
        if (path.endsWith('.html') || path.endsWith('.htm')) {
            const scriptPattern = /<script[^>]*>([\s\S]*?)<\/script>/gi;
            let scriptMatch;
            while ((scriptMatch = scriptPattern.exec(content)) !== null) {
                const scriptContent = scriptMatch[1];
                analyzeJavaScriptContent(scriptContent, file.path + " (inline script)");
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
    if (findings.length > 0) {
        findings.unshift({
            file: "PACKAGE_OVERVIEW",
            type: "UNICODE_OBFUSCATION_SUMMARY",
            total_findings: findings.length,
            high_severity: highSeverityCount,
            medium_severity: mediumSeverityCount,
            severity: overallRisk,
            reason: `Unicode obfuscation detection summary`,
            snippet: `Found ${findings.length} unicode obfuscation indicators`
        });
    }
    
    return {
        rule: "rule15_unicode_obfuscation",
        description: "Detects Unicode homoglyph obfuscation in identifiers",
        findings,
        risk: overallRisk
    };
};