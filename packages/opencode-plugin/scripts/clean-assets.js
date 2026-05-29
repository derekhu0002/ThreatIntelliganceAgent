import { rmSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const assetsRoot = path.resolve(__dirname, "..", "assets");

rmSync(assetsRoot, { recursive: true, force: true });
console.log(`Removed generated assets at ${assetsRoot}`);
