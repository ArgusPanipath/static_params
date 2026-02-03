/**
 * Rule 10: README/Metadata Deception Detection
 * Detects mismatches between claimed functionality in README/metadata and actual code behavior
 */

const natural = require('natural');
const tokenizer = new natural.WordTokenizer();

function extractKeyTerms(text) {
    if (!text || typeof text !== 'string') return [];
    
    const tokens = tokenizer.tokenize(text.toLowerCase());
    
    // Filter out common stop words and short tokens
    const stopWords = new Set(['the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by']);
    const filtered = tokens.filter(token => 
        token.length > 2 && 
        !stopWords.has(token) &&
        !/^\d+$/.test(token)
    );
    
    // Get unique terms
    return [...new Set(filtered)].slice(0, 20); // Limit to top 20 terms
}

function calculateSimilarity(terms1, terms2) {
    if (terms1.length === 0 || terms2.length === 0) return 0;
    
    const set1 = new Set(terms1);
    const set2 = new Set(terms2);
    
    const intersection = new Set([...set1].filter(x => set2.has(x)));
    const union = new Set([...set1, ...set2]);
    
    return intersection.size / union.size;
}

function extractFunctionSignatures(code) {
    const signatures = [];
    
    // Match function declarations (including arrow functions, async functions, methods)
    const functionRegex = /(?:function\s+(\w+)|const\s+(\w+)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>|let\s+(\w+)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>|(?:async\s+)?(\w+)\s*\([^)]*\)\s*{)/g;
    
    let match;
    while ((match = functionRegex.exec(code)) !== null) {
        const name = match[1] || match[2] || match[3] || match[4];
        if (name && name.length > 1) {
            signatures.push(name.toLowerCase());
        }
    }
    
    // Match class declarations and methods
    const classRegex = /class\s+(\w+)|\.(\w+)\s*\([^)]*\)\s*{/g;
    while ((match = classRegex.exec(code)) !== null) {
        const name = match[1] || match[2];
        if (name && name.length > 1) {
            signatures.push(name.toLowerCase());
        }
    }
    
    // Match exports for module functionality
    const exportRegex = /module\.exports\s*=\s*{([^}]+)}|exports\.(\w+)\s*=/g;
    while ((match = exportRegex.exec(code)) !== null) {
        if (match[1]) {
            const exported = match[1].split(',').map(s => s.split(':')[0].trim());
            signatures.push(...exported.filter(s => s.length > 1).map(s => s.toLowerCase()));
        } else if (match[2]) {
            signatures.push(match[2].toLowerCase());
        }
    }
    
    return [...new Set(signatures)].slice(0, 30); // Limit to top 30 signatures
}

module.exports = function rule10_readme_deception({ files, metadata = {} }) {
    const findings = [];
    
    if (!Array.isArray(files)) {
        return {
            rule: "rule10_readme_deception",
            description: "Detects mismatches between README claims and actual code functionality",
            findings: [],
            risk: "LOW"
        };
    }
    
    // Extract README content if present
    let readmeContent = "";
    const readmeFile = files.find(f => 
        f.path.toLowerCase().includes('readme') || 
        f.path.toLowerCase().includes('.md')
    );
    
    if (readmeFile && readmeFile.content) {
        readmeContent = readmeFile.content;
    } else if (metadata.readme) {
        readmeContent = metadata.readme;
    }
    
    if (!readmeContent) {
        return {
            rule: "rule10_readme_deception",
            description: "Detects mismatches between README claims and actual code functionality",
            findings: [],
            risk: "LOW"
        };
    }
    
    // Combine all JavaScript files for analysis
    let combinedCode = "";
    for (const file of files) {
        if (file.path.match(/\.(js|jsx|ts|tsx)$/)) {
            combinedCode += (file.content || "") + "\n";
        }
    }
    
    if (!combinedCode.trim()) {
        return {
            rule: "rule10_readme_deception",
            description: "Detects mismatches between README claims and actual code functionality",
            findings: [],
            risk: "LOW"
        };
    }
    
    // Extract key terms from README
    const readmeTerms = extractKeyTerms(readmeContent);
    
    // Extract function signatures from code
    const codeSignatures = extractFunctionSignatures(combinedCode);
    
    // Calculate similarity
    const similarity = calculateSimilarity(readmeTerms, codeSignatures);
    
    // Flag suspicious mismatches
    if (similarity < 0.1 && readmeTerms.length > 5) {
        const readmeSample = readmeContent.length > 100 
            ? readmeContent.substring(0, 100) + "..." 
            : readmeContent;
        
        findings.push({
            file: readmeFile ? readmeFile.path : "README/metadata",
            type: "README_CODE_MISMATCH",
            similarity: (similarity * 100).toFixed(1) + "%",
            readme_keywords: readmeTerms.slice(0, 10),
            code_functions: codeSignatures.slice(0, 10),
            snippet: readmeSample,
            severity: "MEDIUM",
            reason: "Low similarity between README description and actual code functionality may indicate deception"
        });
    }
    
    // Also check for suspicious claims in README
    const suspiciousClaims = [
        "security patch",
        "official",
        "critical fix",
        "emergency update",
        "vulnerability fix",
        "zero-day",
        "malware removal",
        "virus scan",
        "bitcoin",
        "cryptocurrency",
        "wallet",
        "password",
        "key",
        "token",
        "secret"
    ];
    
    const lowerReadme = readmeContent.toLowerCase();
    const foundClaims = suspiciousClaims.filter(claim => lowerReadme.includes(claim));
    
    if (foundClaims.length > 0 && similarity < 0.2) {
        findings.push({
            file: readmeFile ? readmeFile.path : "README/metadata",
            type: "SUSPICIOUS_README_CLAIMS",
            claims: foundClaims,
            similarity: (similarity * 100).toFixed(1) + "%",
            snippet: foundClaims.join(", "),
            severity: "HIGH",
            reason: "README makes suspicious security/cryptocurrency claims but code doesn't match functionality"
        });
    }
    
    return {
        rule: "rule10_readme_deception",
        description: "Detects mismatches between README claims and actual code functionality",
        findings,
        risk: findings.length > 0 ? "MEDIUM" : "LOW"
    };
};