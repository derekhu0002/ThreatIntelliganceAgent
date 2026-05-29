import { existsSync, readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import YAML from "yaml";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PACKAGE_ASSETS_DIR = path.join(__dirname, "assets");
const SOURCE_OPENCODE_DIR = path.resolve(__dirname, "..", "..", "agent_app", "opencode_app", ".opencode");
const DEFAULT_AGENT = "安全运营助手";
const DEFAULT_AI4X_MCP_URL = "http://localhost:8000/mcp";

function resolveAssetsDir() {
  if (existsSync(path.join(PACKAGE_ASSETS_DIR, "agents"))) {
    return PACKAGE_ASSETS_DIR;
  }
  if (existsSync(path.join(SOURCE_OPENCODE_DIR, "agents"))) {
    return SOURCE_OPENCODE_DIR;
  }
  throw new Error("Cannot find opencode plugin assets. Run npm pack or keep agent_app/opencode_app/.opencode available during local development.");
}

function normalizeOptions(options = {}) {
  return {
    ai4xMcpUrl: options.ai4xMcpUrl || DEFAULT_AI4X_MCP_URL,
    defaultAgent: options.defaultAgent || DEFAULT_AGENT,
    injectInstructions: options.injectInstructions !== false,
    injectMcp: options.injectMcp !== false,
    setDefaultAgent: options.setDefaultAgent !== false,
  };
}

function parseAgentFile(filePath) {
  const text = readFileSync(filePath, "utf8");
  const match = text.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$/);
  if (!match) {
    throw new Error(`Agent file is missing YAML frontmatter: ${filePath}`);
  }

  const frontmatter = YAML.parse(match[1]) || {};
  return {
    ...frontmatter,
    prompt: match[2].trimStart(),
  };
}

function loadAgents(agentsDir) {
  const agents = {};
  for (const entry of readdirSync(agentsDir, { withFileTypes: true })) {
    if (!entry.isFile() || !entry.name.endsWith(".md")) {
      continue;
    }

    const agentName = path.basename(entry.name, ".md");
    agents[agentName] = parseAgentFile(path.join(agentsDir, entry.name));
  }

  return agents;
}

function pushUnique(items, value) {
  if (!items.includes(value)) {
    items.push(value);
  }
}

export default async function ai4xOpenCodePlugin(_input, rawOptions = {}) {
  const options = normalizeOptions(rawOptions);
  const assetsDir = resolveAssetsDir();
  const agentsDir = path.join(assetsDir, "agents");
  const skillsDir = path.join(assetsDir, "skills");
  const instructionsPath = path.join(assetsDir, "GLOBAL_INSTRUCTIONS.md");
  const agents = loadAgents(agentsDir);

  return {
    config: (cfg) => {
      cfg.skills = cfg.skills || {};
      cfg.skills.paths = cfg.skills.paths || [];
      pushUnique(cfg.skills.paths, skillsDir);

      cfg.agent = {
        ...agents,
        ...(cfg.agent || {}),
      };

      if (options.setDefaultAgent) {
        cfg.default_agent = options.defaultAgent;
      }

      if (options.injectInstructions) {
        cfg.instructions = cfg.instructions || [];
        pushUnique(cfg.instructions, instructionsPath);
      }

      if (options.injectMcp) {
        cfg.mcp = cfg.mcp || {};
        cfg.mcp.ai4x = {
          type: "remote",
          url: options.ai4xMcpUrl,
          ...(cfg.mcp.ai4x || {}),
        };
      }
    },
  };
}
