import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import YAML from "yaml";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ASSETS_DIR = path.join(__dirname, "assets");
const AGENTS_DIR = path.join(ASSETS_DIR, "agents");
const SKILLS_DIR = path.join(ASSETS_DIR, "skills");
const INSTRUCTIONS_PATH = path.join(ASSETS_DIR, "GLOBAL_INSTRUCTIONS.md");
const DEFAULT_AGENT = "安全运营助手";
const DEFAULT_AI4X_MCP_URL = "http://localhost:8000/mcp";

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

function loadAgents() {
  const agents = {};
  for (const entry of readdirSync(AGENTS_DIR, { withFileTypes: true })) {
    if (!entry.isFile() || !entry.name.endsWith(".md")) {
      continue;
    }

    const agentName = path.basename(entry.name, ".md");
    agents[agentName] = parseAgentFile(path.join(AGENTS_DIR, entry.name));
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
  const agents = loadAgents();

  return {
    config: (cfg) => {
      cfg.skills = cfg.skills || {};
      cfg.skills.paths = cfg.skills.paths || [];
      pushUnique(cfg.skills.paths, SKILLS_DIR);

      cfg.agent = {
        ...agents,
        ...(cfg.agent || {}),
      };

      if (options.setDefaultAgent) {
        cfg.default_agent = options.defaultAgent;
      }

      if (options.injectInstructions) {
        cfg.instructions = cfg.instructions || [];
        pushUnique(cfg.instructions, INSTRUCTIONS_PATH);
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
