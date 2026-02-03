// test/rule18.test.js

const rule18 = require("../services/rule18.wasm-binary");

const testCases = [
  {
    name: "Direct WASM API usage",
    code: `
      WebAssembly.instantiate(wasmBuffer);
    `
  },
  {
    name: "Embedded WASM base64 payload",
    code: `
      const wasm = "AGFzbQEAAAABBgFgAX8BfwMCAQAHBwEDZmliAA==";
    `
  },
  {
    name: "Embedded EXE payload",
    code: `
      const bin = "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    `
  },
  {
    name: "Safe base64 string",
    code: `
      const img = Buffer.from("iVBORw0KGgoAAAANSUhEUgAA", "base64");
    `
  }
];

testCases.forEach(tc => {
  const findings = rule18.run({ sourceCode: tc.code });
  const safe = findings.every(f => f.severity !== "HIGH");

  console.log(`${tc.name} → safe: ${safe}`);

  if (findings.length > 0) {
    console.log("  findings:", findings);
  }
});
