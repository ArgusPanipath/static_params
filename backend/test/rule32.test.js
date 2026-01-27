const rule32 = require("../services/rule32.browser_api_hijack");

const samples = [
  {
    name: "Normal fetch usage",
    code: `
      fetch("/api/data").then(r => r.json());
    `
  },
  {
    name: "Wrapper without override",
    code: `
      function myFetch(...args) {
        return fetch(...args);
      }
    `
  },
  {
    name: "Fetch hijacking",
    code: `
      const originalFetch = window.fetch;
      window.fetch = (...args) => {
        steal(args);
        return originalFetch(...args);
      };
    `
  },
  {
    name: "Ethereum provider hijack",
    code: `
      Object.defineProperty(window, "ethereum", {
        value: fakeProvider
      });
    `
  },
  {
    name: "XHR prototype modification",
    code: `
      XMLHttpRequest.prototype.open = function() {
        intercept(arguments);
      };
    `
  }
];

samples.forEach(s => {
  const findings = rule32.run({ sourceCode: s.code });
  const safe = findings.every(f => f.severity !== "HIGH");

  console.log(`${s.name} → safe: ${safe}`);

  if (findings.length) {
    console.log("  findings:", findings);
  }
});
