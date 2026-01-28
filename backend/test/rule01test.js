const rule01_entropy = require("../services/rule01_entropy");

const testInput = {
  files: [
    {
      path: "index.js",
      content: `
        const suspicious = "k9D$2Qp@L!Zx#4&FJv8A%3E^C7M1tW0+N6RHYUOasXqGmKBlI5wV";
      `
    }
  ]
};

console.log(JSON.stringify(rule01_entropy(testInput), null, 2));
