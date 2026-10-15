const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } = require("node:fs");
const { tmpdir } = require("node:os");
const { join, resolve } = require("node:path");

const root = resolve(__dirname, "..");
const lock = JSON.parse(readFileSync(join(root, "package-lock.json"), "utf8"));
for (const [name, pkg] of Object.entries(lock.packages)) {
  if (pkg.resolved) assert.equal(new URL(pkg.resolved).origin, "https://registry.npmjs.org", name);
}
const directory = mkdtempSync(join(tmpdir(), "fiberd-package-"));
try {
  execFileSync("npm", ["pack", "--pack-destination", directory], { cwd: root, stdio: "inherit" });
  const tarball = readdirSync(directory).find((name) => name.endsWith(".tgz"));
  assert.ok(tarball);
  writeFileSync(join(directory, "package.json"), JSON.stringify({
    private: true,
    type: "module",
    dependencies: { "@fiberd/client": `file:./${tarball}` },
  }));
  execFileSync("npm", ["install", "--ignore-scripts", "--registry=https://registry.npmjs.org/", "--no-audit", "--no-fund"], { cwd: directory, stdio: "inherit" });
  assert.ok(!readdirSync(join(directory, "node_modules/@fiberd/client/dist")).some(
    (name) => name.includes(".test.") || name.startsWith("testhelpers."),
  ), "test files must not ship in the package");
  for (const name of ["LICENSE", "NOTICE"]) {
    assert.equal(
      readFileSync(join(directory, "node_modules/@fiberd/client", name), "utf8"),
      readFileSync(resolve(root, "../..", name), "utf8"),
    );
  }
  execFileSync(process.execPath, ["--input-type=commonjs", "-e", `
    const { Client, Fence, Kind, Shed } = require("@fiberd/client");
    require("node:assert/strict").equal(new Fence("g", 1n, 2n).toString(), "g/1/2");
    if (typeof Client.dialTls !== "function" || Kind.CREATE !== 0 || !(new Shed(1, "", "") instanceof Error)) {
      throw new Error("CommonJS exports are incomplete");
    }
  `], { cwd: directory, stdio: "inherit" });
  execFileSync(process.execPath, ["--input-type=module", "-e", `
    import { Client, Fence, Kind, Fiber } from "@fiberd/client";
    if (typeof Client.dial !== "function" || typeof Fiber.prototype.dialHandoff !== "function"
      || new Fence("g", 1n, 2n).seq !== 2n || Kind.RESUME !== 2) {
      throw new Error("ES module exports are incomplete");
    }
  `], { cwd: directory, stdio: "inherit" });
  writeFileSync(join(directory, "consumer.mts"), `
    import { Client, type Fiber, type Status, type Token } from "@fiberd/client";
    const client: Client = Client.dial("localhost:7443");
    const token: Token = async () => "jwt";
    const fiber: Fiber = await client.clone(token, { deadlineMs: 500, timeoutMs: 1000 });
    const epoch: bigint = fiber.fence.epoch;
    await client.park(fiber, { sync: true });
    await client.release(fiber.id, { discard: true });
    for await (const value of client.watch()) {
      const status: Status = value;
      const bytes: bigint = status.wUsedBytes;
      break;
    }
    client.close();
  `);
  execFileSync(resolve(root, "node_modules/.bin/tsc"), [
    "--noEmit", "--strict", "--target", "ES2022", "--module", "NodeNext", join(directory, "consumer.mts"),
  ], { cwd: directory, stdio: "inherit" });
  console.log("Packed SDK: CommonJS, ES modules, declarations and license files verified.");
} finally {
  rmSync(directory, { recursive: true, force: true });
}
