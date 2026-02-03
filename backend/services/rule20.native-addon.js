// services/rule20.native-addon.js

module.exports = {
  ruleId: 20,
  severity: "HIGH",
  requires: ["fileList", "bindingGyp", "buildScripts"],

  run: ({ fileList = [], bindingGyp = "", buildScripts = "" }) => {
    const findings = [];

    const hasNodeBinary = fileList.some(f => f.endsWith(".node"));
    const hasCppSource = fileList.some(f =>
      f.endsWith(".cc") || f.endsWith(".cpp") || f.endsWith(".c")
    );

    // 1️⃣ Native binary without source code
    if (hasNodeBinary && !hasCppSource) {
      findings.push({
        rule: 20,
        severity: "HIGH",
        message: "Native .node binary found without corresponding C/C++ source files"
      });
    }

    // 2️⃣ Suspicious compiler / linker flags
    if (bindingGyp) {
      const suspiciousFlags = [
        "-fno-stack-protector",
        "-z execstack",
        "-Wl,--no-as-needed",
        "-shared",
        "-s"
      ];

      suspiciousFlags.forEach(flag => {
        if (bindingGyp.includes(flag)) {
          findings.push({
            rule: 20,
            severity: "HIGH",
            message: `Suspicious compiler/linker flag detected in binding.gyp: ${flag}`
          });
        }
      });

      // 3️⃣ Obfuscated or non-standard include paths
      if (/(\.\.\/){3,}|\/tmp\/|\/var\/tmp\//i.test(bindingGyp)) {
        findings.push({
          rule: 20,
          severity: "INFO",
          message: "Non-standard or obfuscated include paths detected in binding.gyp"
        });
      }
    }

    // 4️⃣ External binary downloads in build scripts
    if (buildScripts) {
      const externalBinaryRegex =
        /(curl|wget).*(\.so|\.dll|\.dylib)/i;

      if (externalBinaryRegex.test(buildScripts)) {
        findings.push({
          rule: 20,
          severity: "HIGH",
          message: "Build script downloads external native binaries"
        });
      }
    }

    return findings;
  }
};
