function calculateEntropy(str) {
  const freq = {};
  for (const char of str) {
    freq[char] = (freq[char] || 0) + 1;
  }

  let entropy = 0;
  const len = str.length;

  for (const char in freq) {
    const p = freq[char] / len;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}

module.exports = function rule01_entropy({ files }) {
  const findings = [];

  if (!Array.isArray(files)) {
    return {
      rule: "rule01_entropy",
      description: "Detects high-entropy encoded or obfuscated strings",
      findings: [],
      risk: "LOW"
    };
  }

  // ✅ FIXED regex
  const stringRegex = /(["'`])((?:\\.|(?!\1).){20,})\1/g;

  for (const file of files) {
    const content = file.content || "";
    let match;

    while ((match = stringRegex.exec(content)) !== null) {
      const value = match[2];
      const entropy = calculateEntropy(value);
      const isBase64Like = /^[A-Za-z0-9+/=]+$/.test(value);

      if (
        entropy >= 5.0 ||
        (isBase64Like && value.length >= 20 && entropy >= 4.2)
      ) {
        findings.push({
          file: file.path,
          type: "HIGH_ENTROPY_STRING",
          entropy: entropy.toFixed(2),
          length: value.length,
          snippet: value.slice(0, 40) + "...",
          severity: "HIGH",
          reason: "High-entropy or encoded string may indicate obfuscated payload"
        });
      }
    }
  }

  return {
    rule: "rule01_entropy",
    description: "Detects high-entropy encoded or obfuscated strings",
    findings,
    risk: findings.length > 0 ? "HIGH" : "LOW"
  };
};
