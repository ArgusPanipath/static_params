const rule06 = require("../services/rule06_filesystem_access");

const testInput = {
  files: [
    {
      path: "index.js",
      content: `
        const fs = require("fs");
        fs.readFileSync("/etc/passwd");
        fs.readFileSync(process.env.HOME + "/.ssh/id_rsa");
      `
    }
  ]
};

console.log(JSON.stringify(rule06(testInput), null, 2));
