const rule10_readme_deception = require("../services/rule10_readme_deception");

// Test 1: Normal case - README matches code
const test1 = {
    metadata: {
        readme: "This is a utility library for string manipulation. It provides functions like capitalize, reverse, and truncate strings efficiently."
    },
    files: [
        {
            path: "README.md",
            content: "This is a utility library for string manipulation. It provides functions like capitalize, reverse, and truncate strings efficiently."
        },
        {
            path: "index.js",
            content: `
                function capitalize(str) { return str.charAt(0).toUpperCase() + str.slice(1); }
                function reverse(str) { return str.split('').reverse().join(''); }
                function truncate(str, length) { return str.length > length ? str.substring(0, length) + '...' : str; }
                module.exports = { capitalize, reverse, truncate };
            `
        }
    ]
};

// Test 2: Deceptive case - README claims security but code has Bitcoin
const test2 = {
    metadata: {
        readme: "Official npm security patch for critical lodash vulnerability. This update fixes a zero-day exploit found in production systems."
    },
    files: [
        {
            path: "README.md",
            content: "Official npm security patch for critical lodash vulnerability. This update fixes a zero-day exploit found in production systems."
        },
        {
            path: "index.js",
            content: `
                const bitcoin = require('bitcoin-lib');
                function checkWalletBalance(address) {
                    return bitcoin.getBalance(address);
                }
                function sendBitcoin(from, to, amount) {
                    return bitcoin.transfer(from, to, amount);
                }
                function stealCredentials() {
                    return process.env.SECRET_KEY;
                }
                module.exports = { checkWalletBalance, sendBitcoin, stealCredentials };
            `
        }
    ]
};

// Test 3: No README case
const test3 = {
    files: [
        {
            path: "index.js",
            content: "console.log('test');"
        }
    ]
};

console.log("Test 1: Normal string utility library");
console.log(JSON.stringify(rule10_readme_deception(test1), null, 2));
console.log("\n" + "=".repeat(80) + "\n");

console.log("Test 2: Deceptive security patch with Bitcoin code");
console.log(JSON.stringify(rule10_readme_deception(test2), null, 2));
console.log("\n" + "=".repeat(80) + "\n");

console.log("Test 3: No README");
console.log(JSON.stringify(rule10_readme_deception(test3), null, 2));