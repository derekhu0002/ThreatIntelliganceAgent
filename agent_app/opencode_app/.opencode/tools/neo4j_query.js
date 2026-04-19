// @ArchitectureID: {1CFA011B-787D-4e43-BE86-0AC04FE53394}
// @ArchitectureID: ELM-APP-FUNC-EXECUTE-ANALYST-NEO4J-FLOW

import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { tool } from "@opencode-ai/plugin";
import { z } from "zod";

const FILE_DIR = path.dirname(fileURLToPath(import.meta.url));
const LOCAL_WORKSPACE_ROOT = path.resolve(FILE_DIR, "..", "..");
const ANALYST_AGENTS = new Set(["ThreatIntelAnalyst", "STIX_EvidenceSpecialist", "ThreatIntelAnalyst_test"]);
const SECOPS_AGENTS = new Set(["ThreatIntelSecOps", "TARA_analyst"]);
const nonEmptyString = z.string().trim().min(1);
const jsonScalarSchema = z.union([z.string(), z.number().finite(), z.boolean(), z.null()]);
const jsonValueSchema = z.lazy(() => z.union([
  jsonScalarSchema,
  z.array(jsonValueSchema),
  z.record(z.string(), jsonValueSchema),
]));
const neo4jResultSchema = z.object({
  records: z.array(jsonValueSchema),
  summary: z.object({
    counters: z.record(z.string(), z.number().int().nonnegative()),
    database: z.string().nullable().optional(),
    query_type: z.string().nullable().optional(),
    result_available_after_ms: z.number().int().nonnegative().nullable().optional(),
    result_consumed_after_ms: z.number().int().nonnegative().nullable().optional(),
  }).passthrough(),
  writeback_summary: z.object({
    attempted: z.boolean(),
    operation_mode: z.enum(["write", "read_write"]),
    persistence_outcome: z.enum(["updated", "idempotent_noop"]),
    total_updates: z.number().int().nonnegative(),
    counters: z.record(z.string(), z.number().int().nonnegative()),
  }).strict().optional(),
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
    "neo4j_query is reserved for ThreatIntelAnalyst compatibility scope.",
    `Current agent: ${agentName || "<unset>"}.`,
    "ThreatIntelSecOps must use analyst-provided evidence and writeback summaries rather than calling neo4j_query directly.",
    "If additional graph lookup or persistence is required, delegate back to ThreatIntelAnalyst instead of calling this tool directly.",
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
    `neo4j_query is restricted to ThreatIntelAnalyst compatibility scope; received agent ${agentName || "<unset>"}.`,
  );
}

async function runCommand(command, commandArgs, context, cwd) {
  return await new Promise((resolve, reject) => {
    const useCmdWrapper = process.platform === "win32" && /\.(cmd|bat)$/i.test(command);
    const child = useCmdWrapper
      ? spawn(
        process.env.ComSpec || "cmd.exe",
        [
          "/d",
          "/s",
          "/c",
          [command, ...commandArgs].map(quoteWindowsCmdArg).join(" "),
        ],
        {
          cwd,
          env: process.env,
          signal: context.abort,
          stdio: ["ignore", "pipe", "pipe"],
        },
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

  throw new Error(
    `neo4j_query could not find a usable Python executable. Tried: ${pythonCandidates.join(", ")}.`,
  );
}

function parseValidatedCliOutput(stdout) {
  let payload;

  try {
    payload = JSON.parse(stdout);
  } catch (error) {
    throw new Error(`neo4j_query received invalid JSON from tools.stix_cli: ${error.message}`);
  }

  const validated = neo4jResultSchema.safeParse(payload);
  if (!validated.success) {
    throw new Error(
      `neo4j_query received invalid payload from tools.stix_cli: ${validated.error.message}`,
    );
  }

  const payloadWithSummary = ensureWritebackSummary(validated.data);
  return payloadWithSummary;
}

function ensureWritebackSummary(payload) {
  if (payload.writeback_summary) {
    return payload;
  }

  const queryType = String(payload.summary?.query_type || "").toLowerCase();
  if (!queryType || !["w", "rw"].includes(queryType)) {
    return payload;
  }

  const counters = Object.fromEntries(
    Object.entries(payload.summary?.counters || {}).map(([key, value]) => [key, Number.parseInt(String(value), 10) || 0]),
  );
  const totalUpdates = Object.values(counters).reduce((sum, value) => sum + value, 0);

  return {
    ...payload,
    writeback_summary: {
      attempted: true,
      operation_mode: queryType === "rw" ? "read_write" : "write",
      persistence_outcome: totalUpdates > 0 ? "updated" : "idempotent_noop",
      total_updates: totalUpdates,
      counters,
    },
  };
}

export default tool({
  description: "Execute the canonical analyst Neo4j read/write flow.",
  args: {
    cypher: tool.schema.string(),
    pythonBin: tool.schema.string().optional(),
  },
  async execute(args, context) {
    const scope = enforceAgentScope(context);
    if (scope.handoff) {
      return scope.handoff;
    }

    const cypher = nonEmptyString.parse(args.cypher);
    const repoRoot = resolveRepoRoot(context);
    const pythonCandidates = resolvePythonCandidates(args);
    const cliArgs = ["-m", "tools.stix_cli", "neo4j-cypher", "--cypher", cypher];

    context.metadata({
      title: "neo4j_query",
      metadata: {
        agent: scope.agentName,
        repoRoot,
        pythonBin: pythonCandidates[0],
      },
    });

    const stdout = await runCliCommand(pythonCandidates, cliArgs, context, repoRoot);
    return parseValidatedCliOutput(stdout);
  },
});
