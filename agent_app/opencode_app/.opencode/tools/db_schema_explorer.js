// @ArchitectureID: ELM-APP-COMP-SCHEMA-EXPLORER

import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { tool } from "@opencode-ai/plugin";
import { z } from "zod";

const FILE_DIR = path.dirname(fileURLToPath(import.meta.url));
const LOCAL_WORKSPACE_ROOT = path.resolve(FILE_DIR, "..", "..");
const DEFAULT_STIX_DATA_PATH = "data/stix_samples/threat_intel_bundle.json";
const ANALYST_AGENTS = new Set(["ThreatIntelAnalyst", "STIX_EvidenceSpecialist"]);
const SECOPS_AGENTS = new Set(["ThreatIntelSecOps", "TARA_analyst"]);
const nonEmptyString = z.string().trim().min(1);
const entityTypeSchema = z.object({
  entity_type: nonEmptyString,
  stix_types: z.array(nonEmptyString),
  key_fields: z.array(nonEmptyString),
  relationship_types: z.array(nonEmptyString),
}).strict();
const schemaSummarySchema = z.object({
  schema_version: nonEmptyString,
  schema_first_guidance: nonEmptyString,
  supported_query_fields: z.array(nonEmptyString),
  relationship_fields: z.array(nonEmptyString),
  relationship_types: z.array(nonEmptyString),
  entity_types: z.array(entityTypeSchema),
}).strict();

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
    if (existsSync(path.join(normalized, "tools", "stix_cli", "__main__.py"))) {
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
    "db_schema_explorer is reserved for ThreatIntelAnalyst compatibility scope.",
    `Current agent: ${agentName || "<unset>"}.`,
    "ThreatIntelSecOps must use the analyst-provided STIX evidence already returned by ThreatIntelPrimary.",
    "If additional schema lookup is required, delegate back to ThreatIntelAnalyst instead of calling this tool directly.",
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
  {
    const details = agentName || "<unset>";
    throw new Error(
      `db_schema_explorer is restricted to ThreatIntelAnalyst compatibility scope; received agent ${details}.`,
    );
  }
}

async function runCommand(command, commandArgs, context, cwd) {
  return await new Promise((resolve, reject) => {
    const useShell = process.platform === "win32" && /\.(cmd|bat)$/i.test(command);
    const child = spawn(command, commandArgs, {
      cwd,
      env: process.env,
      signal: context.abort,
      shell: useShell,
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

async function runCliCommand(pythonCandidates, cliArgs, context, cwd) {
  let lastError;

  for (const pythonBin of pythonCandidates) {
    try {
      return await runCommand(pythonBin, cliArgs, context, cwd);
    } catch (error) {
      lastError = error;
      if (error?.code !== "ENOENT") {
        throw error;
      }
    }
  }

  const attempted = pythonCandidates.join(", ");
  throw new Error(`db_schema_explorer could not find a usable Python executable. Tried: ${attempted}.`);
}

function parseValidatedCliOutput(stdout) {
  let payload;

  try {
    payload = JSON.parse(stdout);
  } catch (error) {
    throw new Error(
      `db_schema_explorer received invalid JSON from tools.stix_cli: ${error.message}`,
    );
  }

  const validated = schemaSummarySchema.safeParse(payload);
  if (!validated.success) {
    throw new Error(
      `db_schema_explorer received invalid schema-summary payload from tools.stix_cli: ${validated.error.message}`,
    );
  }

  return validated.data;
}

export default tool({
  description: "Explore the local STIX schema summary before building structured evidence queries.",
  args: {
    data: tool.schema.string().optional(),
    pythonBin: tool.schema.string().optional(),
  },
  async execute(args, context) {
    const scope = enforceAgentScope(context);
    if (scope.handoff) {
      return scope.handoff;
    }

    const repoRoot = resolveRepoRoot(context);
    const pythonCandidates = resolvePythonCandidates(args);
    const dataPath = args.data
      ? path.resolve(repoRoot, args.data)
      : path.resolve(repoRoot, DEFAULT_STIX_DATA_PATH);

    context.metadata({
      title: "db_schema_explorer",
      metadata: {
        agent: scope.agentName,
        pythonBin: pythonCandidates[0],
        repoRoot,
      },
    });

    const stdout = await runCliCommand(
      pythonCandidates,
      ["-m", "tools.stix_cli", "--data", dataPath, "schema-summary"],
      context,
      repoRoot,
    );
    return JSON.stringify(parseValidatedCliOutput(stdout), null, 2);
  },
});