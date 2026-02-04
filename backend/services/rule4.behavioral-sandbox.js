// services/rule4.behavioral-sandbox.js

module.exports = {
  ruleId: 4,
  severity: "HIGH",
  requires: ["sandboxReport"],

  run: ({ sandboxReport }) => {
    if (!sandboxReport) return [];

    const findings = [];

    const {
      networkRequests = [],
      syscalls = [],
      fileWrites = [],
      executedCommands = []
    } = sandboxReport;

    // 1️⃣ Unexpected outbound network access
    if (networkRequests.length > 0) {
      findings.push({
        rule: 4,
        severity: "HIGH",
        message: "Package performs outbound network communication during execution"
      });
    }

    // 2️⃣ Suspicious system calls
    const dangerousSyscalls = ["execve", "fork", "clone"];
    if (syscalls.some(sc => dangerousSyscalls.includes(sc))) {
      findings.push({
        rule: 4,
        severity: "HIGH",
        message: "Suspicious process execution system calls detected"
      });
    }

    // 3️⃣ Writes outside application directory
    if (fileWrites.some(p => p.startsWith("/tmp") || p.startsWith("/etc"))) {
      findings.push({
        rule: 4,
        severity: "HIGH",
        message: "Package writes files to sensitive system locations"
      });
    }

    // 4️⃣ Shell or command execution
    if (executedCommands.some(cmd =>
      cmd.includes("sh") || cmd.includes("bash")
    )) {
      findings.push({
        rule: 4,
        severity: "CRITICAL",
        message: "Package executed shell commands during runtime"
      });
    }

    return findings;
  }
};
