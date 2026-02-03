/**
 * Rule 11: Binary/Native Module Detection
 * Detects packages containing compiled binaries that bypass static analysis
 */

module.exports = function rule11_binary_detection({ files }) {
    const findings = [];
    
    if (!Array.isArray(files)) {
        return {
            rule: "rule11_binary_detection",
            description: "Detects compiled binaries in packages that bypass static analysis",
            findings: [],
            risk: "LOW"
        };
    }
    
    // Common binary/executable extensions
    const binaryExtensions = new Set([
        // Windows executables
        '.exe', '.dll', '.sys', '.drv', '.ocx', '.cpl', '.scr',
        // Linux/Unix binaries
        '.so', '.so.', '.a', '.o', '.ko',
        // macOS binaries
        '.dylib', '.bundle',
        // General binaries
        '.bin', '.dat', '.elf', '.obj',
        // Script binaries/compiled
        '.pyc', '.pyo', '.pyd', '.pyw',
        // Java compiled
        '.class', '.jar',
        // .NET
        '.nupkg', '.msi', '.cab',
        // Other suspicious
        '.sh', '.bat', '.cmd', '.ps1', '.vbs', '.com'
    ]);
    
    // Common source code extensions (expected in packages)
    const sourceExtensions = new Set([
        '.js', '.jsx', '.ts', '.tsx',
        '.py', '.rb', '.java', '.c', '.cpp', '.h', '.hpp',
        '.go', '.rs', '.php', '.swift',
        '.html', '.css', '.scss', '.less',
        '.json', '.yml', '.yaml', '.xml',
        '.md', '.txt', '.rst'
    ]);
    
    const binaryFiles = [];
    const suspiciousPaths = new Set([
        'bin/', 'dist/', 'build/', 'release/', 'target/',
        'node_modules/.bin/', 'scripts/', 'tools/'
    ]);
    
    for (const file of files) {
        const path = file.path.toLowerCase();
        const filename = path.split('/').pop();
        
        // Skip common legitimate files
        if (filename === 'package.json' || filename === 'package-lock.json' || 
            filename === 'readme.md' || filename === 'license') {
            continue;
        }
        
        // Check for binary extensions
        const isBinary = binaryExtensions.has(file.extension && file.extension.toLowerCase()) ||
            binaryExtensions.has('.' + filename.split('.').pop()) ||
            binaryExtensions.has(path.slice(-4)) ||
            binaryExtensions.has(path.slice(-5)) ||
            binaryExtensions.has(path.slice(-6));
        
        // Check for suspicious file names (even without extension)
        const suspiciousNames = [
            'install', 'setup', 'update', 'patch', 'loader',
            'inject', 'hook', 'payload', 'malware', 'virus',
            'keylogger', 'rat', 'backdoor', 'rootkit', 'exploit'
        ];
        
        const hasSuspiciousName = suspiciousNames.some(name => 
            filename.includes(name) && filename.length > 3
        );
        
        // Check for suspicious paths
        const inSuspiciousPath = Array.from(suspiciousPaths).some(suspPath => 
            path.includes(suspPath)
        );
        
        if (isBinary || hasSuspiciousName) {
            const fileInfo = {
                file: file.path,
                filename: filename,
                size: file.size || 'unknown',
                is_binary: isBinary,
                suspicious_name: hasSuspiciousName,
                suspicious_path: inSuspiciousPath
            };
            
            binaryFiles.push(fileInfo);
            
            let severity = "LOW";
            let reason = "Binary file detected";
            
            if (hasSuspiciousName) {
                severity = "MEDIUM";
                reason = `Binary with suspicious name detected: ${filename}`;
            }
            
            if (inSuspiciousPath && !path.includes('node_modules/')) {
                severity = "MEDIUM";
                reason = `Binary in suspicious directory: ${file.path}`;
            }
            
            // Check if binary has no corresponding source file
            const baseName = filename.split('.')[0];
            const hasSource = files.some(f => 
                f.path !== file.path && 
                f.path.toLowerCase().includes(baseName) &&
                sourceExtensions.has('.' + f.path.split('.').pop().toLowerCase())
            );
            
            if (!hasSource && isBinary) {
                severity = "HIGH";
                reason = `Binary file without corresponding source code: ${file.path}`;
            }
            
            findings.push({
                file: file.path,
                type: "BINARY_FILE",
                filename: filename,
                size: file.size || 'unknown',
                severity: severity,
                reason: reason,
                snippet: `Binary/executable file detected: ${filename}`
            });
        }
    }
    
    // Calculate statistics
    const totalFiles = files.length;
    const binaryCount = binaryFiles.length;
    const binaryPercentage = totalFiles > 0 ? (binaryCount / totalFiles * 100).toFixed(1) : 0;
    
    // Additional finding if high percentage of binaries
    if (binaryPercentage > 10 && binaryCount > 2) {
        findings.push({
            file: "PACKAGE_ROOT",
            type: "HIGH_BINARY_PERCENTAGE",
            binary_count: binaryCount,
            total_files: totalFiles,
            percentage: binaryPercentage + "%",
            severity: "MEDIUM",
            reason: `Package contains ${binaryPercentage}% binary files, unusually high for JavaScript package`,
            snippet: `High binary content: ${binaryCount}/${totalFiles} files`
        });
    }
    
    return {
        rule: "rule11_binary_detection",
        description: "Detects compiled binaries in packages that bypass static analysis",
        findings,
        risk: findings.some(f => f.severity === "HIGH") ? "HIGH" : 
              findings.some(f => f.severity === "MEDIUM") ? "MEDIUM" : 
              findings.length > 0 ? "LOW" : "LOW"
    };
};