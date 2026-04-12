// @ArchitectureID: ELM-APP-COMP-AGENT-ORCH

import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { tool } from "@opencode-ai/plugin";

const FILE_DIR = path.dirname(fileURLToPath(import.meta.url));
const FALLBACK_WORKSPACE_ROOT = path.resolve(FILE_DIR, "..");

const CANONICAL_ROLE_MAP = {
  ThreatIntelliganceCommander: "ThreatIntelPrimary",
  STIX_EvidenceSpecialist: "ThreatIntelAnalyst",
  TARA_analyst: "ThreatIntelSecOps",
};

const LEGACY_ROLE_MAP = Object.fromEntries(
  Object.entries(CANONICAL_ROLE_MAP).map(([legacy, canonical]) => [canonical, legacy]),
);

function resolveWorkspaceRoot(context) {
  if (context.directory && existsSync(path.join(context.directory, "agents"))) {
    return context.directory;
  }

  return FALLBACK_WORKSPACE_ROOT;
}

function readJson(filePath) {
  return JSON.parse(readFileSync(filePath, "utf8"));
}

function readAgentDefinition(workspaceRoot, relativePath) {
  const absolutePath = path.resolve(workspaceRoot, relativePath);
  return {
    path: relativePath,
    preview: readFileSync(absolutePath, "utf8").split("\n").slice(0, 8).join("\n"),
  };
}

function canonicalRoleName(name) {
  return CANONICAL_ROLE_MAP[name] || name;
}

function legacyRoleName(name) {
  return LEGACY_ROLE_MAP[name] || name;
}

function roleDefinitionPath(name) {
  return `agents/${name}.md`;
}

function flattenMatches(bundle) {
  return (bundle.searches || []).flatMap((search) => search.matches || []);
}

function evidenceSpecialist(input, workspaceRoot) {
  const matches = flattenMatches(input.evidence_bundle);
  const relationships = (input.evidence_bundle.relationships || []).flatMap((view) => view.relationships || []);
  const namedMatches = [...new Set(matches.map((match) => match.name).filter(Boolean))];
  const relatedPeers = [...new Set(relationships.map((item) => item.peer && item.peer.name).filter(Boolean))];
  const relationshipTypes = [...new Set(relationships.map((item) => item.relationship_type).filter(Boolean))];
  const confidenceValues = matches.map((match) => match.confidence).filter((value) => typeof value === "number");
  const averageConfidence = confidenceValues.length
    ? Math.round(confidenceValues.reduce((sum, value) => sum + value, 0) / confidenceValues.length)
    : null;

  return {
    role: canonicalRoleName("STIX_EvidenceSpecialist"),
    legacy_role: "STIX_EvidenceSpecialist",
    responsibility: "Correlate the pushed event with local STIX entities and relationships.",
    findings: [
      `Matched entities: ${namedMatches.join(", ") || "none"}.`,
      `Related peer entities: ${relatedPeers.join(", ") || "none"}.`,
      `Observed relationship types: ${relationshipTypes.join(", ") || "none"}.`,
      averageConfidence !== null
        ? `Average confidence across matched STIX objects: ${averageConfidence}.`
        : "No explicit confidence score was present in matched STIX objects.",
    ],
    supporting_evidence_refs: matches.slice(0, 4).map((match) => match.id),
    definition_source: readAgentDefinition(workspaceRoot, roleDefinitionPath(canonicalRoleName("STIX_EvidenceSpecialist"))),
    compatibility_definition_source: readAgentDefinition(workspaceRoot, roleDefinitionPath("STIX_EvidenceSpecialist")),
  };
}

function taraAnalyst(input, evidenceOutput, workspaceRoot) {
  const evidenceText = evidenceOutput.findings.join(" ");
  const mentionsActor = /APT28/i.test(evidenceText);
  const mentionsPhishing = /Spearphishing|phishing/i.test(`${input.event.summary} ${evidenceText}`);
  const severity = String(input.event.severity || "medium").toLowerCase();

  const confidence = mentionsActor ? "high" : severity === "high" ? "medium-high" : "medium";
  const verdict = mentionsActor ? "likely-known-threat-activity" : "suspicious-activity-needs-hunt";
  const recommendations = [
    "Block or monitor the indicator and associated IP infrastructure in network controls.",
    "Hunt for related authentication, email, and outbound-connection telemetry tied to the observable.",
    "Review users or assets exposed to phishing delivery paths and reset affected credentials if needed.",
  ];
  if (mentionsActor || mentionsPhishing) {
    recommendations.push("Pivot on actor-linked malware and phishing techniques in endpoint and email detections.");
  }

  return {
    role: canonicalRoleName("TARA_analyst"),
    legacy_role: "TARA_analyst",
    responsibility: "Assess likely threat significance, impact, and recommended actions.",
    findings: [
      `Risk verdict: ${verdict}.`,
      `Assessment confidence: ${confidence}.`,
      mentionsPhishing
        ? "Delivery and post-compromise tradecraft are consistent with phishing-driven credential access."
        : "The available data indicates suspicious infrastructure activity that still requires broader hunting.",
    ],
    recommended_actions: recommendations,
    verdict,
    confidence,
    definition_source: readAgentDefinition(workspaceRoot, roleDefinitionPath(canonicalRoleName("TARA_analyst"))),
    compatibility_definition_source: readAgentDefinition(workspaceRoot, roleDefinitionPath("TARA_analyst")),
  };
}

function commander(input, evidenceOutput, riskOutput, workspaceRoot) {
  const supportingEntities = [
    ...new Set([
      ...flattenMatches(input.evidence_bundle).map((match) => match.name).filter(Boolean),
      ...(input.evidence_bundle.relationships || []).flatMap((view) =>
        (view.relationships || []).map((item) => item.peer && item.peer.name).filter(Boolean),
      ),
    ]),
  ];

  return {
    role: canonicalRoleName("ThreatIntelliganceCommander"),
    legacy_role: "ThreatIntelliganceCommander",
    responsibility:
      "Synthesize specialist findings into the final structured threat-intelligence assessment and assemble the remote TASK-009 result contract.",
    findings: [
      `Event ${input.event.event_id} from ${input.event.source} was correlated with ${supportingEntities.length} relevant STIX entities.`,
      evidenceOutput.findings[0],
      riskOutput.findings[0],
    ],
    final_assessment: {
      summary: supportingEntities.includes("APT28")
        ? "The pushed indicator aligns with known APT28-linked phishing activity and warrants rapid containment plus targeted hunting."
        : "The pushed indicator is suspicious and should be investigated with targeted hunting based on the matched local STIX evidence.",
      confidence: riskOutput.confidence,
      verdict: riskOutput.verdict,
      recommended_actions: riskOutput.recommended_actions,
      supporting_entities: supportingEntities,
      assembled_by: canonicalRoleName("ThreatIntelliganceCommander"),
    },
    definition_source: readAgentDefinition(
      workspaceRoot,
      roleDefinitionPath(canonicalRoleName("ThreatIntelliganceCommander")),
    ),
    compatibility_definition_source: readAgentDefinition(workspaceRoot, roleDefinitionPath("ThreatIntelliganceCommander")),
  };
}

function loadInput(args, context) {
  if (args.inputJson) {
    return JSON.parse(args.inputJson);
  }

  if (!args.inputPath) {
    throw new Error("threat_intel_orchestrator requires `inputJson` or `inputPath`.");
  }

  const baseDirectory = context.directory || context.worktree || FALLBACK_WORKSPACE_ROOT;
  const absolutePath = path.isAbsolute(args.inputPath)
    ? args.inputPath
    : path.resolve(baseDirectory, args.inputPath);

  return readJson(absolutePath);
}

export default tool({
  description: "Run the deterministic threat-intel orchestration compatibility stub.",
  args: {
    inputPath: tool.schema.string().optional(),
    inputJson: tool.schema.string().optional(),
  },
  async execute(args, context) {
    const workspaceRoot = resolveWorkspaceRoot(context);
    const input = loadInput(args, context);
    const evidenceOutput = evidenceSpecialist(input, workspaceRoot);
    const riskOutput = taraAnalyst(input, evidenceOutput, workspaceRoot);
    const commanderOutput = commander(input, evidenceOutput, riskOutput, workspaceRoot);

    const output = {
      run_id: input.run_context.run_id,
      participants: [
        canonicalRoleName("ThreatIntelliganceCommander"),
        canonicalRoleName("STIX_EvidenceSpecialist"),
        canonicalRoleName("TARA_analyst"),
      ],
      legacy_participants: ["ThreatIntelliganceCommander", "STIX_EvidenceSpecialist", "TARA_analyst"],
      role_outputs: [evidenceOutput, riskOutput, commanderOutput],
      final_assessment: commanderOutput.final_assessment,
      traceability: {
        evidence_refs: [...new Set([...(evidenceOutput.supporting_evidence_refs || [])])],
        definition_sources: [
          evidenceOutput.definition_source.path,
          riskOutput.definition_source.path,
          commanderOutput.definition_source.path,
        ],
        compatibility_definition_sources: [
          evidenceOutput.compatibility_definition_source.path,
          riskOutput.compatibility_definition_source.path,
          commanderOutput.compatibility_definition_source.path,
        ],
        role_aliases: {
          ThreatIntelPrimary: legacyRoleName("ThreatIntelPrimary"),
          ThreatIntelAnalyst: legacyRoleName("ThreatIntelAnalyst"),
          ThreatIntelSecOps: legacyRoleName("ThreatIntelSecOps"),
        },
        assembled_by: canonicalRoleName("ThreatIntelliganceCommander"),
      },
    };

    context.metadata({
      title: "threat_intel_orchestrator",
      metadata: {
        participants: output.participants,
      },
    });

    return JSON.stringify(output, null, 2);
  },
});
