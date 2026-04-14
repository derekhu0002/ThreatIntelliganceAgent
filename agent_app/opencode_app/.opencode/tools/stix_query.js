// @ArchitectureID: ELM-APP-COMP-STIX-NATIVE-TOOL
// @ArchitectureID: ELM-FUNC-VALIDATE-STIX-QUERY-CLI-OUTPUT

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
const stixObjectSummarySchema = z.object({
  id: nonEmptyString,
  type: nonEmptyString,
  name: z.string().nullable().optional(),
  description: z.string().nullable().optional(),
  pattern: z.string().nullable().optional(),
  value: z.string().nullable().optional(),
  confidence: z.number().finite().nullable().optional(),
}).strict();
const stixSearchResultSchema = z.object({
  query: nonEmptyString,
  match_count: z.number().int().nonnegative(),
  matches: z.array(stixObjectSummarySchema),
}).strict().superRefine((payload, ctx) => {
  if (payload.match_count !== payload.matches.length) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: "match_count must equal the number of matches.",
      path: ["match_count"],
    });
  }
});
const stixNeighborRelationshipSchema = z.object({
  relationship_id: nonEmptyString,
  relationship_type: nonEmptyString,
  direction: z.enum(["incoming", "outgoing"]),
  peer: stixObjectSummarySchema,
}).strict();
const stixNeighborsResultSchema = z.object({
  stix_id: nonEmptyString,
  object: stixObjectSummarySchema,
  relationship_count: z.number().int().nonnegative(),
  relationships: z.array(stixNeighborRelationshipSchema),
}).strict().superRefine((payload, ctx) => {
  if (payload.relationship_count !== payload.relationships.length) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: "relationship_count must equal the number of relationships.",
      path: ["relationship_count"],
    });
  }
});

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

function parseValidatedCliOutput(stdout, command) {
  let payload;

  try {
    payload = JSON.parse(stdout);
  } catch (error) {
    throw new Error(
      `stix_query received invalid JSON from tools.stix_cli: ${error.message}`,
    );
  }

  const schema = command === "search" ? stixSearchResultSchema : stixNeighborsResultSchema;
  const validated = schema.safeParse(payload);
  if (!validated.success) {
    throw new Error(
      `stix_query received invalid ${command} payload from tools.stix_cli: ${validated.error.message}`,
    );
  }

  return validated.data;
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

    const stdout = await runCommand(pythonBin, cliArgs, context, repoRoot);
    return parseValidatedCliOutput(stdout, args.command);
  },
});
