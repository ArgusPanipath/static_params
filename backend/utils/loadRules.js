const fs = require("fs");
const path = require("path");

module.exports = function loadRules() {
  const servicesDir = path.join(__dirname, "../services");

  return fs
    .readdirSync(servicesDir)
    .filter(file => file.endsWith(".js"))
    .map(file => require(path.join(servicesDir, file)));
};
