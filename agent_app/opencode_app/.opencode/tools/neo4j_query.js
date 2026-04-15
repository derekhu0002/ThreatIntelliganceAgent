// @ArchitectureID: {1CFA011B-787D-4e43-BE86-0AC04FE53394}

import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { tool } from "@opencode-ai/plugin";
import { z } from "zod";

const FILE_DIR = path.dirname(fileURLToPath(import.meta.url));
const LOCAL_WORKSPACE_ROOT = path.resolve(FILE_DIR, "..", "..");
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

  return validated.data;
}

export default tool({
  description: "Execute native Neo4j Cypher and return clean JSON.",
  args: {
    cypher: tool.schema.string(),
    pythonBin: tool.schema.string().optional(),
  },
  async execute(args, context) {
    const cypher = nonEmptyString.parse(args.cypher);
    const repoRoot = resolveRepoRoot(context);
    const pythonCandidates = resolvePythonCandidates(args);
    const cliArgs = ["-m", "tools.stix_cli", "neo4j-cypher", "--cypher", cypher];

    context.metadata({
      title: "neo4j_query",
      metadata: {
        repoRoot,
        pythonBin: pythonCandidates[0],
      },
    });

    const stdout = await runCliCommand(pythonCandidates, cliArgs, context, repoRoot);
    return parseValidatedCliOutput(stdout);
  },
});
