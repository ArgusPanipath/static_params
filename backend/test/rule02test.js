const rule02 = require("../services/rule02_dangerous_api");

const testInput = {
  files: [
    {
      path: "index.js",
      content: `
        const fs = require("fs");
        const { exec } = require("child_process");

        exec("ls");
        eval("console.log('danger')");
        fs.readFileSync("/etc/passwd");
      `
    }
  ]
};

console.log(JSON.stringify(rule02(testInput), null, 2));
