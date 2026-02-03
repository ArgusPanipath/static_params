const rule11_binary_detection = require("../services/rule11_binary_detection");

// Test 1: Pure JavaScript package (no binaries)
const test1 = {
    files: [
        {
            path: "package.json",
            content: '{"name": "pure-js-lib", "version": "1.0.0"}',
            size: 1024
        },
        {
            path: "index.js",
            content: "module.exports = () => console.log('Hello');",
            size: 2048
        },
        {
            path: "lib/utils.js",
            content: "module.exports = { add: (a,b) => a+b };",
            size: 4096
        },
        {
            path: "README.md",
            content: "# Pure JS Library",
            size: 512
        }
    ]
};

// Test 2: Package with suspicious Windows binary
const test2 = {
    files: [
        {
            path: "package.json",
            content: '{"name": "text-parser", "version": "1.0.0"}',
            size: 1024
        },
        {
            path: "index.js",
            content: "module.exports = { parse: () => {} };",
            size: 2048
        },
        {
            path: "bin/installer.exe",
            content: "MZ...binary content...",  // Simulated binary
            size: 1024000
        },
        {
            path: "lib/parser.dll",
            content: "binary DLL content",
            size: 512000
        }
    ]
};

// Test 3: Package with Linux shared objects
const test3 = {
    files: [
        {
            path: "package.json",
            content: '{"name": "native-addon", "version": "2.0.0"}',
            size: 1024
        },
        {
            path: "index.js",
            content: "const native = require('./build/Release/addon.node');",
            size: 2048
        },
        {
            path: "build/Release/addon.node",
            content: "ELF binary",
            size: 2048000
        },
        {
            path: "lib/libhelper.so.1.2.3",
            content: "shared object binary",
            size: 1024000
        }
    ]
};

// Test 4: Package with suspiciously named files
const test4 = {
    files: [
        {
            path: "package.json",
            content: '{"name": "utility-tool", "version": "1.5.0"}',
            size: 1024
        },
        {
            path: "index.js",
            content: "console.log('Utility tool');",
            size: 2048
        },
        {
            path: "scripts/keylogger.bat",
            content: "@echo off\nstart keylogger.exe",
            size: 512
        },
        {
            path: "tools/rat-loader",
            content: "binary content",
            size: 1536000
        },
        {
            path: "src/update-payload",
            content: "malicious binary",
            size: 1024000
        }
    ]
};

// Test 5: Mixed package with high binary percentage
const test5 = {
    files: [
        {
            path: "package.json",
            size: 1024
        },
        {
            path: "main.bin",
            size: 2048000
        },
        {
            path: "loader.exe",
            size: 1536000
        },
        {
            path: "config.dll",
            size: 512000
        },
        {
            path: "data.dat",
            size: 1024000
        },
        {
            path: "README.txt",
            size: 512
        }
    ]
};

console.log("Test 1: Pure JavaScript package (no binaries)");
console.log(JSON.stringify(rule11_binary_detection(test1), null, 2));
console.log("\n" + "=".repeat(80) + "\n");

console.log("Test 2: Text parser with Windows binaries");
console.log(JSON.stringify(rule11_binary_detection(test2), null, 2));
console.log("\n" + "=".repeat(80) + "\n");

console.log("Test 3: Native addon with Linux shared objects");
console.log(JSON.stringify(rule11_binary_detection(test3), null, 2));
console.log("\n" + "=".repeat(80) + "\n");

console.log("Test 4: Package with suspiciously named files");
console.log(JSON.stringify(rule11_binary_detection(test4), null, 2));
console.log("\n" + "=".repeat(80) + "\n");

console.log("Test 5: High percentage binary package");
console.log(JSON.stringify(rule11_binary_detection(test5), null, 2));