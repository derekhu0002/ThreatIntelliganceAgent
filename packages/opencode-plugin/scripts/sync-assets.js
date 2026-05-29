import { cpSync, existsSync, mkdirSync, rmSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const packageRoot = path.resolve(__dirname, "..");
const repoRoot = path.resolve(packageRoot, "..", "..");
const sourceRoot = path.join(repoRoot, "agent_app", "opencode_app", ".opencode");
const assetsRoot = path.join(packageRoot, "assets");

const entries = [
  ["agents", "agents"],
  ["skills", "skills"],
  ["plugins", "plugins"],
  ["GLOBAL_INSTRUCTIONS.md", "GLOBAL_INSTRUCTIONS.md"],
  ["workspace.contract.json", "workspace.contract.json"],
];

function syncAssets() {
  if (!existsSync(sourceRoot)) {
    throw new Error(`Source .opencode directory not found: ${sourceRoot}`);
  }

  rmSync(assetsRoot, { recursive: true, force: true });
  mkdirSync(assetsRoot, { recursive: true });

  for (const [source, target] of entries) {
    const sourcePath = path.join(sourceRoot, source);
    if (!existsSync(sourcePath)) {
      continue;
    }
    cpSync(sourcePath, path.join(assetsRoot, target), { recursive: true });
  }

  console.log(`Synced plugin assets from ${sourceRoot}`);
}

syncAssets();
