// services/rule18.wasm-binary.js

module.exports = {
  ruleId: 18,
  severity: "HIGH",
  requires: ["sourceCode"],

  run: ({ sourceCode }) => {
    if (!sourceCode || typeof sourceCode !== "string") return [];

    const findings = [];

    // 1️⃣ Direct WebAssembly usage
    if (/WebAssembly\.(instantiate|compile|instantiateStreaming)/.test(sourceCode)) {
      findings.push({
        rule: 18,
        severity: "HIGH",
        message: "Direct WebAssembly API usage detected"
      });
    }

    // 2️⃣ .wasm file references
    if (/\.wasm(['"`])/i.test(sourceCode)) {
      findings.push({
        rule: 18,
        severity: "HIGH",
        message: "WASM binary reference detected"
      });
    }

    // 3️⃣ Large base64 strings (>1KB)
    // const base64Regex = /['"`]([A-Za-z0-9+/=]{1024,})['"`]/g;
    const base64Regex = /['"`]([A-Za-z0-9+/=]{50,})['"`]/g;

    const base64Matches = [...sourceCode.matchAll(base64Regex)];

    // base64Matches.forEach(match => {
    //   const blob = match[1];

    //   // Binary signatures
    //   if (
    //     blob.startsWith("AGFzbQ") || // WASM (\0asm)
    //     blob.startsWith("TVqQ") ||   // MZ (Windows EXE)
    //     blob.startsWith("f0VMRg")    // ELF
    //   ) {
    //     findings.push({
    //       rule: 18,
    //       severity: "HIGH",
    //       message: "Embedded binary payload detected in base64 string"
    //     });
    //   } else {
    //     findings.push({
    //       rule: 18,
    //       severity: "INFO",
    //       message: "Large base64-encoded blob detected (manual review recommended)"
    //     });
    //   }
    // });

    base64Matches.forEach(match => {
  const blob = match[1];

  // High-risk binary signatures (regardless of size)
  if (
    blob.startsWith("TVqQ") ||    // MZ (Windows EXE)
    blob.startsWith("AGFzbQ") ||  // WASM
    blob.startsWith("f0VMRg")     // ELF
  ) {
    findings.push({
      rule: 18,
      severity: "HIGH",
      message: "Embedded executable binary detected in base64 string"
    });
    return;
  }

  // Large unknown base64 blob
  if (blob.length > 1024) {
    findings.push({
      rule: 18,
      severity: "INFO",
      message: "Large base64-encoded binary blob detected"
    });
  }
});


    // 4️⃣ Buffer.from with base64 / binary encoding
    if (/Buffer\.from\([^,]+,\s*['"](base64|binary)['"]\)/i.test(sourceCode)) {
      findings.push({
        rule: 18,
        severity: "HIGH",
        message: "Binary data decoding detected using Buffer.from"
      });
    }

    return findings;
  }
};
