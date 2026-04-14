// @ArchitectureID: ELM-APP-COMP-SCHEMA-EXPLORER

import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { tool } from "@opencode-ai/plugin";
import { z } from "zod";

const FILE_DIR = path.dirname(fileURLToPath(import.meta.url));
const FALLBACK_REPO_ROOT = path.resolve(FILE_DIR, "..", "..", "..", "..");
const DEFAULT_STIX_DATA_PATH = "data/stix_samples/threat_intel_bundle.json";
const ALLOWED_AGENTS = new Set(["ThreatIntelAnalyst", "STIX_EvidenceSpecialist"]);
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
    enforceAgentScope(context);

    const repoRoot = resolveRepoRoot(context);
    const pythonBin = args.pythonBin
      || process.env.PYTHON_BIN
      || (process.platform === "win32" ? "python" : "python3");
    const dataPath = args.data
      ? path.resolve(repoRoot, args.data)
      : path.resolve(repoRoot, DEFAULT_STIX_DATA_PATH);

    context.metadata({
      title: "db_schema_explorer",
      metadata: {
        agent: resolveAgentName(context),
        repoRoot,
      },
    });

    const stdout = await runCommand(
      pythonBin,
      ["-m", "tools.stix_cli", "--data", dataPath, "schema-summary"],
      context,
      repoRoot,
    );
    return parseValidatedCliOutput(stdout);
  },
});