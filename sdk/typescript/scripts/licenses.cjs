const { copyFileSync } = require("node:fs");
const { resolve } = require("node:path");

for (const name of ["LICENSE", "NOTICE"]) {
  copyFileSync(resolve(__dirname, "../../..", name), resolve(__dirname, "..", name));
}
