#!/usr/bin/env node
// @ArchitectureID: ELM-APP-COMP-STIX-NATIVE-TOOL

const { spawnSync } = require("child_process");
const path = require("path");

const ALLOWED_AGENTS = new Set(["ThreatIntelAnalyst", "STIX_EvidenceSpecialist"]);

function resolveRepoRoot() {
  return path.resolve(__dirname, "..", "..", "..", "..");
}

function resolveAgentName() {
  return process.env.OPENCODE_AGENT_NAME || process.env.THREAT_INTEL_AGENT_ROLE || "";
}

function enforceAgentScope() {
  const agentName = resolveAgentName().trim();
  if (!ALLOWED_AGENTS.has(agentName)) {
    const details = agentName || "<unset>";
    throw new Error(
      `stix_query is restricted to ThreatIntelAnalyst compatibility scope; received agent ${details}.`
    );
  }
}

function main() {
  enforceAgentScope();

  const repoRoot = resolveRepoRoot();
  const pythonBin = process.env.PYTHON_BIN || "python3";
  const result = spawnSync(pythonBin, ["-m", "tools.stix_cli", ...process.argv.slice(2)], {
    cwd: repoRoot,
    encoding: "utf8",
    env: process.env,
  });

  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    const stderr = (result.stderr || "").trim();
    throw new Error(stderr || `tools.stix_cli exited with status ${result.status}`);
  }

  process.stdout.write(result.stdout);
}

if (require.main === module) {
  main();
}

module.exports = {
  ALLOWED_AGENTS,
  resolveAgentName,
};
