import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import plugin from "../index.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const packageRoot = path.resolve(__dirname, "..");
const assetsRoot = path.join(packageRoot, "assets");

assert.equal(existsSync(path.join(assetsRoot, "agents", "安全运营助手.md")), true);
assert.equal(existsSync(path.join(assetsRoot, "skills", "ioc-triage-indicator-priority", "SKILL.md")), true);
assert.equal(existsSync(path.join(assetsRoot, "plugins", "introduce-before-talk.ts")), true);
assert.equal(existsSync(path.join(assetsRoot, "GLOBAL_INSTRUCTIONS.md")), true);

const hooks = await plugin({}, {});
assert.equal(typeof hooks.config, "function");

const cfg = {};
hooks.config(cfg);

assert.equal(cfg.default_agent, "安全运营助手");
assert.equal(cfg.mcp.ai4x.type, "remote");
assert.equal(cfg.mcp.ai4x.url, "http://localhost:8000/mcp");
assert.equal(cfg.skills.paths.length, 1);
assert.equal(cfg.skills.paths[0], path.join(assetsRoot, "skills"));
assert.equal(typeof cfg.agent["安全运营助手"].prompt, "string");
assert.equal(cfg.agent["安全运营助手"].mode, "primary");
assert.equal(cfg.instructions[0], path.join(assetsRoot, "GLOBAL_INSTRUCTIONS.md"));

const customHooks = await plugin({}, {
  ai4xMcpUrl: "http://example.test/mcp",
  injectInstructions: false,
  setDefaultAgent: false,
});
const customCfg = {};
customHooks.config(customCfg);

assert.equal(customCfg.default_agent, undefined);
assert.equal(customCfg.instructions, undefined);
assert.equal(customCfg.mcp.ai4x.url, "http://example.test/mcp");

console.log("Plugin verification passed.");
