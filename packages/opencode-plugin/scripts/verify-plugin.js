import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import plugin from "../index.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const packageRoot = path.resolve(__dirname, "..");
const repoRoot = path.resolve(packageRoot, "..", "..");
const sourceRoot = path.join(repoRoot, "agent_app", "opencode_app", ".opencode");
const packagedAssetsRoot = path.join(packageRoot, "assets");
const expectedAssetsRoot = existsSync(path.join(packagedAssetsRoot, "agents")) ? packagedAssetsRoot : sourceRoot;

assert.equal(existsSync(path.join(expectedAssetsRoot, "agents", "安全运营助手.md")), true);
assert.equal(existsSync(path.join(expectedAssetsRoot, "skills", "ioc-triage-indicator-priority", "SKILL.md")), true);
assert.equal(existsSync(path.join(expectedAssetsRoot, "plugins", "introduce-before-talk.ts")), true);
assert.equal(existsSync(path.join(expectedAssetsRoot, "GLOBAL_INSTRUCTIONS.md")), true);

const hooks = await plugin({}, {});
assert.equal(typeof hooks.config, "function");

const cfg = {};
hooks.config(cfg);

assert.equal(cfg.default_agent, "安全运营助手");
assert.equal(cfg.mcp.ai4x.type, "remote");
assert.equal(cfg.mcp.ai4x.url, "http://localhost:8000/mcp");
assert.equal(cfg.skills.paths.length, 1);
assert.equal(cfg.skills.paths[0], path.join(expectedAssetsRoot, "skills"));
assert.equal(typeof cfg.agent["安全运营助手"].prompt, "string");
assert.equal(cfg.agent["安全运营助手"].mode, "primary");
assert.equal(cfg.instructions[0], path.join(expectedAssetsRoot, "GLOBAL_INSTRUCTIONS.md"));

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
