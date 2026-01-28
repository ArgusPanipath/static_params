/**
 * Rule 05: Network Destination Analysis
 * Detects suspicious external domains or IPs in source code
 */

const SAFE_DOMAINS = [
    "npmjs.org",
    "github.com",
    "githubusercontent.com"
  ];
  
  const SUSPICIOUS_TLDS = [".ru", ".cn", ".tk", ".ml"];
  
  function isPrivateIP(ip) {
    return (
      ip.startsWith("10.") ||
      ip.startsWith("192.168.") ||
      ip.startsWith("172.16.") ||
      ip.startsWith("127.")
    );
  }
  
  function extractDestinations(files) {
    const results = new Set();
    const urlRegex = /(https?:\/\/[^\s"'`<>]+)/gi;
    const ipRegex = /\b\d{1,3}(\.\d{1,3}){3}\b/g;
  
    for (const file of files) {
      const content = file.content || "";
  
      let match;
      while ((match = urlRegex.exec(content)) !== null) {
        results.add(match[1]);
      }
  
      while ((match = ipRegex.exec(content)) !== null) {
        results.add(match[0]);
      }
    }
  
    return Array.from(results);
  }
  
  function classifyDestination(dest) {
    // IP address
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(dest)) {
      if (isPrivateIP(dest)) {
        return { risk: "LOW", reason: "Private or localhost IP" };
      }
      return { risk: "HIGH", reason: "Unknown public IP address contacted" };
    }
  
    // Known safe domains
    for (const domain of SAFE_DOMAINS) {
      if (dest.includes(domain)) {
        return { risk: "LOW", reason: "Known safe domain" };
      }
    }
  
    // Suspicious TLDs
    for (const tld of SUSPICIOUS_TLDS) {
      if (dest.endsWith(tld) || dest.includes(tld + "/")) {
        return { risk: "MEDIUM", reason: "Suspicious top-level domain" };
      }
    }
  
    return {
      risk: "MEDIUM",
      reason: "Unknown external destination"
    };
  }
  
  module.exports = function rule05_network_destinations({ files }) {
    const findings = [];
  
    if (!Array.isArray(files)) {
      return {
        rule: "rule05_network_destinations",
        description: "Detects suspicious network destinations",
        findings: [],
        risk: "LOW"
      };
    }
  
    const destinations = extractDestinations(files);
  
    let highRiskCount = 0;
    let mediumRiskCount = 0;
  
    for (const dest of destinations) {
      const classification = classifyDestination(dest);
  
      if (classification.risk === "HIGH") highRiskCount++;
      if (classification.risk === "MEDIUM") mediumRiskCount++;
  
      if (classification.risk !== "LOW") {
        findings.push({
          destination: dest,
          risk: classification.risk,
          reason: classification.reason
        });
      }
    }
  
    let risk = "LOW";
    if (highRiskCount > 0) risk = "HIGH";
    else if (mediumRiskCount > 0) risk = "MEDIUM";
  
    return {
      rule: "rule05_network_destinations",
      description: "Detects suspicious network destinations",
      findings,
      risk
    };
  };
  