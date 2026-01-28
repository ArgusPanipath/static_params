const rule08 = require("../services/rule08_dependency_confusion");

const testInput = {
  packageJson: {
    dependencies: {
      "@mycompany/utils": "^1.0.0",
      "lodash": "^4.17.21"
    }
  }
};

console.log(JSON.stringify(rule08(testInput), null, 2));
