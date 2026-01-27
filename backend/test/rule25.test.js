// const rule25 = require("../services/rule25.minified");

// const files = [
//   {
//     path: "index.js",
//     lines: 1,
//     size: 12000,
//     content: "var a='x'.repeat(10000);"
//   },
//   {
//     path: "utils.js",
//     lines: 20,
//     size: 800,
//     content: "function add(a,b){ return a+b; }"
//   }
// ];

// const findings = rule25.run({ files });
// console.log(findings);


const rule25 = require("../services/rule25.minified");

const files = [
  {
    path: "index.js",
    lines: 1,
    size: 12000,
    content:
      "var _0x9f2a=_0x1b9c('0x2f');function _0x1b9c(a){return a+Math.random().toString(36).substring(2)}"
  }
];

const findings = rule25.run({ files });
console.log(findings);
