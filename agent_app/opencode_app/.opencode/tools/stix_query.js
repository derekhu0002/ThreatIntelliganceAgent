// @ArchitectureID: ELM-APP-COMP-STIX-NATIVE-TOOL

import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { tool } from "@opencode-ai/plugin";

const FILE_DIR = path.dirname(fileURLToPath(import.meta.url));
const FALLBACK_REPO_ROOT = path.resolve(FILE_DIR, "..", "..", "..", "..");
const DEFAULT_STIX_DATA_PATH = "data/stix_samples/threat_intel_bundle.json";
const ALLOWED_AGENTS = new Set(["ThreatIntelAnalyst", "STIX_EvidenceSpecialist"]);

function resolveRepoRoot(context) {
  return context.worktree || FALLBACK_REPO_ROOT;
}

function resolveAgentName(context) {
  return String(
    context.agent || process.env.OPENCODE_AGENT_NAME || process.env.THREAT_INTEL_AGENT_ROLE || "",
  ).trim();
}

function enforceAgentScope(context) {
  const agentName = resolveAgentName(context);
  if (!ALLOWED_AGENTS.has(agentName)) {
    const details = agentName || "<unset>";
    throw new Error(
      `stix_query is restricted to ThreatIntelAnalyst compatibility scope; received agent ${details}.`,
    );
  }
}

function buildCliArgs(args, repoRoot) {
  if (args.command === "search" && !args.query) {
    throw new Error("stix_query requires `query` when command is `search`.");
  }
  if (args.command === "neighbors" && !args.stixId) {
    throw new Error("stix_query requires `stixId` when command is `neighbors`.");
  }

  const cliArgs = ["-m", "tools.stix_cli"];
  const dataPath = args.data
    ? path.resolve(repoRoot, args.data)
    : path.resolve(repoRoot, DEFAULT_STIX_DATA_PATH);

  cliArgs.push("--data", dataPath, args.command);

  if (args.command === "search") {
    cliArgs.push("--query", args.query);
  } else {
    cliArgs.push("--stix-id", args.stixId);
  }

  return cliArgs;
}

async function runCommand(command, commandArgs, context, cwd) {
  return await new Promise((resolve, reject) => {
    const child = spawn(command, commandArgs, {
      cwd,
      env: process.env,
      signal: context.abort,
      stdio: ["ignore", "pipe", "pipe"],
    });

    let stdout = "";
    let stderr = "";

    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
    });

    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });

    child.on("error", (error) => {
      reject(error);
    });

    child.on("close", (code) => {
      if (code === 0) {
        resolve(stdout);
        return;
      }

      reject(new Error(stderr.trim() || `tools.stix_cli exited with status ${code}`));
    });
  });
}

export default tool({
  description: "Query local STIX evidence for analyst workflows.",
  args: {
    command: tool.schema.enum(["search", "neighbors"]),
    query: tool.schema.string().optional(),
    stixId: tool.schema.string().optional(),
    data: tool.schema.string().optional(),
    pythonBin: tool.schema.string().optional(),
  },
  async execute(args, context) {
    enforceAgentScope(context);

    const repoRoot = resolveRepoRoot(context);
    const pythonBin = args.pythonBin || process.env.PYTHON_BIN || "python3";
    const cliArgs = buildCliArgs(args, repoRoot);

    context.metadata({
      title: `stix_query ${args.command}`,
      metadata: {
        agent: resolveAgentName(context),
        repoRoot,
      },
    });

    return await runCommand(pythonBin, cliArgs, context, repoRoot);
  },
});
