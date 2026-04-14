// @ArchitectureID: ELM-APP-COMP-STIX-NATIVE-TOOL
// @ArchitectureID: ELM-FUNC-VALIDATE-STIX-QUERY-CLI-OUTPUT

import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { tool } from "@opencode-ai/plugin";
import { z } from "zod";

const FILE_DIR = path.dirname(fileURLToPath(import.meta.url));
const LOCAL_WORKSPACE_ROOT = path.resolve(FILE_DIR, "..", "..");
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
const advancedFilterValueSchema = z.union([nonEmptyString, z.number().finite(), z.boolean()]);
const stixAdvancedFilterRelationshipSchema = z.object({
  relationship_id: nonEmptyString,
  relationship_type: nonEmptyString,
  source: stixObjectSummarySchema,
  target: stixObjectSummarySchema,
}).strict();
const stixAdvancedFilterResultSchema = z.object({
  filters: z.record(nonEmptyString, advancedFilterValueSchema),
  match_count: z.number().int().nonnegative(),
  matches: z.array(stixObjectSummarySchema),
  relationship_count: z.number().int().nonnegative(),
  relationships: z.array(stixAdvancedFilterRelationshipSchema),
}).strict().superRefine((payload, ctx) => {
  if (Object.keys(payload.filters).length === 0) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: "filters must contain at least one schema-derived field.",
      path: ["filters"],
    });
  }
  if (payload.match_count !== payload.matches.length) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: "match_count must equal the number of matches.",
      path: ["match_count"],
    });
  }
  if (payload.relationship_count !== payload.relationships.length) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: "relationship_count must equal the number of relationships.",
      path: ["relationship_count"],
    });
  }
});

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
  if (args.command === "advanced_filter" && !args.filtersJson) {
    throw new Error("stix_query requires `filtersJson` when command is `advanced_filter`.");
  }

  const cliArgs = ["-m", "tools.stix_cli"];
  const dataPath = args.data
    ? path.resolve(repoRoot, args.data)
    : path.resolve(repoRoot, DEFAULT_STIX_DATA_PATH);

  cliArgs.push("--data", dataPath, args.command);

  if (args.command === "search") {
    cliArgs.push("--query", args.query);
  } else if (args.command === "neighbors") {
    cliArgs.push("--stix-id", args.stixId);
  } else {
    cliArgs.push("--filters-json", args.filtersJson);
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
  throw new Error(`stix_query could not find a usable Python executable. Tried: ${attempted}.`);
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

  const schema = command === "search"
    ? stixSearchResultSchema
    : command === "neighbors"
      ? stixNeighborsResultSchema
      : stixAdvancedFilterResultSchema;
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
    command: tool.schema.enum(["search", "neighbors", "advanced_filter"]),
    query: tool.schema.string().optional(),
    stixId: tool.schema.string().optional(),
    filtersJson: tool.schema.string().optional(),
    data: tool.schema.string().optional(),
    pythonBin: tool.schema.string().optional(),
  },
  async execute(args, context) {
    enforceAgentScope(context);

    const repoRoot = resolveRepoRoot(context);
    const pythonCandidates = resolvePythonCandidates(args);
    const cliArgs = buildCliArgs(args, repoRoot);

    context.metadata({
      title: `stix_query ${args.command}`,
      metadata: {
        agent: resolveAgentName(context),
        pythonBin: pythonCandidates[0],
        repoRoot,
      },
    });

    const stdout = await runCliCommand(pythonCandidates, cliArgs, context, repoRoot);
    return parseValidatedCliOutput(stdout, args.command);
  },
});
