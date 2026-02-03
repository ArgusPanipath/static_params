const rule12_crypto_miner = require("../services/rule12_crypto_miner");

// Test 1: Clean package with no crypto
const test1 = {
    files: [
        {
            path: "index.js",
            content: `
                const express = require('express');
                const app = express();
                app.get('/', (req, res) => res.send('Hello'));
                app.listen(3000);
            `
        },
        {
            path: "package.json",
            content: '{"name": "web-server", "dependencies": {"express": "^4.0.0"}}'
        }
    ]
};

// Test 2: Package with Bitcoin wallet address (like UA-Parser-JS attack)
const test2 = {
    files: [
        {
            path: "index.js",
            content: `
                // UA-Parser-JS library
                function parseUserAgent() { return {}; }
                
                // Malicious injected code
                const bitcoinWallet = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
                const ethWallet = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e";
                
                // Mining code
                const miner = require('coinhive');
                miner.start('your-site-key');
                
                // Connection to mining pool
                const ws = new WebSocket('wss://pool.minexmr.com:443');
            `
        }
    ]
};

// Test 3: Sophisticated miner with multiple indicators
const test3 = {
    files: [
        {
            path: "src/miner.js",
            content: `
                // Cryptocurrency miner disguised as analytics
                const CoinHive = require('coin-hive');
                const miner = await CoinHive('SITE_KEY');
                
                // Multiple wallets for redundancy
                const wallets = {
                    bitcoin: "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
                    ethereum: "0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B",
                    monero: "46BeWrHpwXmHDpDEUmZBWZfoQpdc6HaERCNmx1pEYL2rAcuwufPN9rXHHtyUA4QVy66qeFQkn6sfK8aHYjA3jk3o1Bv16em"
                };
                
                // Mining pool configuration
                const poolConfig = {
                    url: "stratum+tcp://xmr.pool.minergate.com:45560",
                    user: wallets.monero,
                    pass: "x"
                };
                
                // Start mining with 50% CPU throttle
                async function startMining() {
                    await miner.start({
                        throttle: 0.5,
                        pool: poolConfig
                    });
                }
                
                // WebAssembly miner for better performance
                const wasmCode = fetch('cryptonight.wasm');
                WebAssembly.instantiate(wasmCode);
            `
        }
    ]
};

// Test 4: Litecoin miner with suspicious comments
const test4 = {
    files: [
        {
            path: "miner-config.js",
            content: `
                // This is NOT a cryptocurrency miner
                // Just a configuration file for analytics
                
                // Litecoin donation address (for "support")
                const donationAddress = "Lg6S8KMN5mF4vZmDzZ7hR5PkQ1qjT8WcBx";
                
                // Mining keywords in comments (trying to avoid detection)
                /*
                * This module handles user analytics
                * Not related to: bitcoin mining, cryptocurrency, hash rate
                * Definitely not: proof of work, mining rig, cpu miner
                */
            `
        }
    ]
};

// Test 5: Package.json with mining dependency
const test5 = {
    files: [
        {
            path: "package.json",
            content: `{
                "name": "analytics-package",
                "version": "2.0.0",
                "dependencies": {
                    "express": "^4.0.0",
                    "coinhive": "^1.0.0",
                    "webcoin-miner": "^0.5.2"
                },
                "scripts": {
                    "start": "node miner.js"
                }
            }`
        }
    ]
};

console.log("Test 1: Clean web server package");
console.log(JSON.stringify(rule12_crypto_miner(test1), null, 2));
console.log("\n" + "=".repeat(80) + "\n");

console.log("Test 2: UA-Parser-JS style attack with Bitcoin wallet");
console.log(JSON.stringify(rule12_crypto_miner(test2), null, 2));
console.log("\n" + "=".repeat(80) + "\n");

console.log("Test 3: Sophisticated miner with multiple wallets and pools");
console.log(JSON.stringify(rule12_crypto_miner(test3), null, 2));
console.log("\n" + "=".repeat(80) + "\n");

console.log("Test 4: Litecoin miner with deceptive comments");
console.log(JSON.stringify(rule12_crypto_miner(test4), null, 2));
console.log("\n" + "=".repeat(80) + "\n");

console.log("Test 5: Package.json with mining dependencies");
console.log(JSON.stringify(rule12_crypto_miner(test5), null, 2));