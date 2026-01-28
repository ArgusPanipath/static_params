const rule03 = require("../services/rule03_code_diff");

const oldFiles = {
  "index.js": "console.log('hello');"
};

const newFiles = {
  "index.js": "console.log('hello');\n".repeat(250)
};

const oldPackageJson = {
  dependencies: {
    lodash: "^4.17.0"
  }
};

const newPackageJson = {
  dependencies: {
    lodash: "^4.17.0",
    "flatmap-stream": "^0.1.0"
  }
};

const result = rule03({
  oldFiles,
  newFiles,
  oldPackageJson,
  newPackageJson,
  versionChange: "patch"
});

console.log(JSON.stringify(result, null, 2));
