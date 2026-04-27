// @ArchitectureID: ELM-APP-COMP-AI4X-QUERY-TOOL

import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { tool } from "@opencode-ai/plugin";
import { z } from "zod";

const FILE_DIR = path.dirname(fileURLToPath(import.meta.url));
const LOCAL_WORKSPACE_ROOT = path.resolve(FILE_DIR, "..", "..");
const ANALYST_AGENTS = new Set(["ThreatIntelAnalyst", "STIX_EvidenceSpecialist", "ThreatIntelAnalyst_test", "ThreatIntelUnknownHuntPrimary"]);
const SECOPS_AGENTS = new Set(["ThreatIntelSecOps", "TARA_analyst"]);
const nonEmptyString = z.string().trim().min(1);
const ai4xCatalogSchema = z.object({
  version: z.string().optional(),
  total_databases: z.number().int().nonnegative().optional(),
  databases: z.array(z.record(z.string(), z.unknown())),
}).passthrough();
const ai4xSchemaResultSchema = z.object({
  source_id: nonEmptyString,
  schema: z.unknown(),
}).passthrough();
const ai4xQueryResultSchema = z.object({
  source_id: nonEmptyString,
  items: z.array(z.unknown()).optional(),
  count: z.number().int().nonnegative().optional(),
}).passthrough();

function resolveRepoRoot(context) {
  const candidates = [
    process.env.THREAT_INTEL_REPO_ROOT,
    context.worktree,
    LOCAL_WORKSPACE_ROOT,
  ];

  for (const candidate of candidates) {
    if (!candidate) {
      continue;
    }

    const normalized = path.resolve(candidate);
    if (existsSync(path.join(normalized, "tools", "ai4x_cli.py"))) {
      return normalized;
    }
  }

  return LOCAL_WORKSPACE_ROOT;
}

function resolvePythonCandidates(args) {
  const requested = args.pythonBin || process.env.PYTHON_BIN;
  if (requested) {
    return [requested];
  }

  return process.platform === "win32"
    ? ["python", "python3"]
    : ["python3", "python"];
}

function resolveAgentName(context) {
  return String(
    context.agent || process.env.OPENCODE_AGENT_NAME || process.env.THREAT_INTEL_AGENT_ROLE || "",
  ).trim();
}

function buildScopeHandoff(agentName) {
  return [
    "ai4x_query is reserved for ThreatIntelAnalyst compatibility scope.",
    `Current agent: ${agentName || "<unset>"}.`,
    "ThreatIntelSecOps must use analyst-provided AI4X data rather than calling ai4x_query directly.",
    "If additional AI4X lookup is required, delegate back to ThreatIntelAnalyst instead of calling this tool directly.",
  ].join("\n");
}

function enforceAgentScope(context) {
  const agentName = resolveAgentName(context);
  if (ANALYST_AGENTS.has(agentName)) {
    return { agentName, handoff: null };
  }
  if (SECOPS_AGENTS.has(agentName)) {
    return { agentName, handoff: buildScopeHandoff(agentName) };
  }

  throw new Error(
    `ai4x_query is restricted to ThreatIntelAnalyst compatibility scope; received agent ${agentName || "<unset>"}.`,
  );
}

function buildCliArgs(args) {
  const cliArgs = ["-m", "tools.ai4x_cli"];
  if (args.baseUrl) {
    cliArgs.push("--base-url", args.baseUrl);
  }
  cliArgs.push(args.command);

  if (args.command === "schema") {
    cliArgs.push("--source-id", args.sourceId);
  }

  if (args.command === "query") {
    cliArgs.push("--source-id", args.sourceId, "--cypher", args.cypher);
    if (args.paramsJson) {
      cliArgs.push("--params-json", args.paramsJson);
    }
    if (Number.isInteger(args.limit)) {
      cliArgs.push("--limit", String(args.limit));
    }
  }

  return cliArgs;
}

async function runCommand(command, commandArgs, context, cwd) {
  return await new Promise((resolve, reject) => {
    const useCmdWrapper = process.platform === "win32" && /\.(cmd|bat)$/i.test(command);
    const child = useCmdWrapper
      ? spawn(
        process.env.ComSpec || "cmd.exe",
        ["/d", "/s", "/c", [command, ...commandArgs].map(quoteWindowsCmdArg).join(" ")],
        { cwd, env: process.env, signal: context.abort, stdio: ["ignore", "pipe", "pipe"] },
      )
      : spawn(command, commandArgs, {
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
    child.on("error", (error) => reject(error));
    child.on("close", (code) => {
      if (code === 0) {
        resolve(stdout);
        return;
      }
      reject(new Error(stderr.trim() || `tools.ai4x_cli exited with status ${code}`));
    });
  });
}

function quoteWindowsCmdArg(value) {
  return `"${String(value).replace(/"/g, '""')}"`;
}

async function runCliCommand(pythonCandidates, cliArgs, context, cwd) {
  for (const pythonBin of pythonCandidates) {
    try {
      return await runCommand(pythonBin, cliArgs, context, cwd);
    } catch (error) {
      if (error?.code !== "ENOENT") {
        throw error;
      }
    }
  }

  throw new Error(`ai4x_query could not find a usable Python executable. Tried: ${pythonCandidates.join(", ")}.`);
}

function parseValidatedCliOutput(stdout, command) {
  let payload;
  try {
    payload = JSON.parse(stdout);
  } catch (error) {
    throw new Error(`ai4x_query received invalid JSON from tools.ai4x_cli: ${error.message}`);
  }

  const schema = command === "catalog"
    ? ai4xCatalogSchema
    : command === "schema"
      ? ai4xSchemaResultSchema
      : ai4xQueryResultSchema;
  const validated = schema.safeParse(payload);
  if (!validated.success) {
    throw new Error(`ai4x_query received invalid payload from tools.ai4x_cli: ${validated.error.message}`);
  }
  return validated.data;
}

export default tool({
  description: "Discover and query the real AI4X Platform API Center.",
  args: {
    command: tool.schema.enum(["catalog", "schema", "query"]),
    sourceId: tool.schema.string().optional(),
    cypher: tool.schema.string().optional(),
    paramsJson: tool.schema.string().optional(),
    limit: tool.schema.number().int().optional(),
    baseUrl: tool.schema.string().optional(),
    pythonBin: tool.schema.string().optional(),
  },
  async execute(args, context) {
    const scope = enforceAgentScope(context);
    if (scope.handoff) {
      return scope.handoff;
    }

    if (args.command !== "catalog") {
      nonEmptyString.parse(args.sourceId);
    }
    if (args.command === "query") {
      nonEmptyString.parse(args.cypher);
    }

    const repoRoot = resolveRepoRoot(context);
    const pythonCandidates = resolvePythonCandidates(args);
    const cliArgs = buildCliArgs(args);

    context.metadata({
      title: "ai4x_query",
      metadata: {
        agent: scope.agentName,
        repoRoot,
        command: args.command,
        sourceId: args.sourceId || null,
        baseUrl: args.baseUrl || null,
      },
    });

    const stdout = await runCliCommand(pythonCandidates, cliArgs, context, repoRoot);
    const payload = parseValidatedCliOutput(stdout, args.command);
    return JSON.stringify(payload);
  },
});