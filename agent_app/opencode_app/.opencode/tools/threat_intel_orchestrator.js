// @ArchitectureID: ELM-APP-COMP-AGENT-ORCH
// MOCK STUB FOR TESTING ONLY - production should delegate to LLM-driven agents.

import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { tool } from "@opencode-ai/plugin";

const FILE_DIR = path.dirname(fileURLToPath(import.meta.url));
const FALLBACK_WORKSPACE_ROOT = path.resolve(FILE_DIR, "..");

const CANONICAL_ROLE_MAP = {
  ThreatIntelligenceCommander: "ThreatIntelPrimary",
  STIX_EvidenceSpecialist: "ThreatIntelAnalyst",
  TARA_analyst: "ThreatIntelSecOps",
};

const LEGACY_ROLE_MAP = Object.fromEntries(
  Object.entries(CANONICAL_ROLE_MAP).map(([legacy, canonical]) => [canonical, legacy]),
);
const RESULT_SCHEMA_VERSION = "threat-intelligence-agent.v1";
const DEFAULT_STIX_BUNDLE_PATH = path.join("..", "data", "stix_samples", "threat_intel_bundle.json");

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

function resolveDataBundlePath(workspaceRoot, explicitPath) {
  const candidate = explicitPath
    ? (path.isAbsolute(explicitPath) ? explicitPath : path.resolve(workspaceRoot, explicitPath))
    : path.resolve(workspaceRoot, DEFAULT_STIX_BUNDLE_PATH);

  if (!existsSync(candidate)) {
    throw new Error(`threat_intel_orchestrator could not locate STIX bundle at ${candidate}.`);
  }

  return candidate;
}

function loadBundle(bundlePath) {
  const payload = readJson(bundlePath);
  if (payload?.type !== "bundle" || !Array.isArray(payload.objects)) {
    throw new Error(`threat_intel_orchestrator expected a STIX bundle at ${bundlePath}.`);
  }
  return payload;
}

function summarizeObject(stixObject) {
  return {
    id: stixObject.id,
    type: stixObject.type,
    name: stixObject.name || stixObject.value || stixObject.relationship_type || null,
    description: stixObject.description || null,
    pattern: stixObject.pattern || null,
    value: stixObject.value || null,
    confidence: typeof stixObject.confidence === "number" ? stixObject.confidence : null,
  };
}

function casefold(value) {
  return String(value || "").trim().toLowerCase();
}

function matchesTerm(stixObject, term) {
  const expected = casefold(term);
  if (!expected) {
    return false;
  }

  return [
    stixObject.id,
    stixObject.type,
    stixObject.name,
    stixObject.description,
    stixObject.pattern,
    stixObject.value,
  ].some((value) => casefold(value).includes(expected));
}

function searchEntities(bundle, term) {
  const matches = (bundle.objects || [])
    .filter((item) => item && item.type !== "relationship" && matchesTerm(item, term))
    .map((item) => summarizeObject(item));

  return {
    query: String(term),
    match_count: matches.length,
    matches,
  };
}

function neighbors(bundle, stixId) {
  const objectsById = new Map((bundle.objects || []).filter((item) => item?.id).map((item) => [item.id, item]));
  const stixObject = objectsById.get(stixId);
  if (!stixObject) {
    throw new Error(`Unknown STIX object id: ${stixId}`);
  }

  const relationships = (bundle.objects || [])
    .filter((item) => item?.type === "relationship")
    .flatMap((relationship) => {
      if (relationship.source_ref === stixId) {
        return [{
          relationship_id: relationship.id,
          relationship_type: relationship.relationship_type,
          direction: "outgoing",
          peer: summarizeObject(objectsById.get(relationship.target_ref) || { id: relationship.target_ref, type: "unknown" }),
        }];
      }
      if (relationship.target_ref === stixId) {
        return [{
          relationship_id: relationship.id,
          relationship_type: relationship.relationship_type,
          direction: "incoming",
          peer: summarizeObject(objectsById.get(relationship.source_ref) || { id: relationship.source_ref, type: "unknown" }),
        }];
      }
      return [];
    });

  return {
    stix_id: stixId,
    object: summarizeObject(stixObject),
    relationship_count: relationships.length,
    relationships,
  };
}

function buildEvidenceBundleFromRequest(input, workspaceRoot) {
  const bundlePath = resolveDataBundlePath(workspaceRoot, input.stix_bundle_path || input.stix_bundle);
  const bundle = loadBundle(bundlePath);
  const searchTerms = [
    input.event?.entity?.name,
    ...(input.event?.observables || []).map((observable) => observable.value),
    ...(input.event?.labels || []),
  ].filter(Boolean);

  const searches = [];
  const candidateIds = [];
  for (const searchTerm of [...new Set(searchTerms)]) {
    const result = searchEntities(bundle, searchTerm);
    searches.push(result);
    for (const match of result.matches.slice(0, 2)) {
      if (match.id && !candidateIds.includes(match.id)) {
        candidateIds.push(match.id);
      }
    }
  }

  const relationships = candidateIds.slice(0, 3).map((stixId) => neighbors(bundle, stixId));
  const uniqueEntityRefs = [...new Set([input.event?.entity?.id, ...candidateIds].filter(Boolean))];
  const relationshipCount = relationships.reduce((sum, item) => sum + Number(item.relationship_count || 0), 0);
  const counters = {
    nodes_created: uniqueEntityRefs.length,
    relationships_created: Math.max(1, relationshipCount),
    properties_set: (input.event?.labels || []).length + (input.event?.observables || []).length + 1,
  };

  return {
    stix_bundle: path.relative(workspaceRoot, bundlePath).replace(/\\/g, "/"),
    searches,
    relationships,
    writeback_summary: {
      attempted: true,
      operation_mode: "read_write",
      persistence_outcome: "updated",
      total_updates: Object.values(counters).reduce((sum, value) => sum + value, 0),
      counters,
    },
  };
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

// MOCK STUB FOR TESTING ONLY - production should delegate to LLM-driven agents.
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

// MOCK STUB FOR TESTING ONLY - production should delegate to LLM-driven agents.
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
    role: canonicalRoleName("ThreatIntelligenceCommander"),
    legacy_role: "ThreatIntelligenceCommander",
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
      assembled_by: canonicalRoleName("ThreatIntelligenceCommander"),
    },
    definition_source: readAgentDefinition(
      workspaceRoot,
      roleDefinitionPath(canonicalRoleName("ThreatIntelligenceCommander")),
    ),
    compatibility_definition_source: readAgentDefinition(workspaceRoot, roleDefinitionPath("ThreatIntelligenceCommander")),
  };
}

function buildStructuredResult(input, workspaceRoot) {
  const evidenceBundle = input.evidence_bundle || buildEvidenceBundleFromRequest(input, workspaceRoot);
  const evidenceOutput = evidenceSpecialist({ ...input, evidence_bundle: evidenceBundle }, workspaceRoot);
  const riskOutput = taraAnalyst(input, evidenceOutput, workspaceRoot);
  const commanderOutput = commander({ ...input, evidence_bundle: evidenceBundle }, evidenceOutput, riskOutput, workspaceRoot);
  const event = input.event || {};
  const relationshipCount = (evidenceBundle.relationships || []).length;
  const evidenceMatchCount = (evidenceBundle.searches || []).reduce((sum, item) => sum + Number(item.match_count || 0), 0);
  const participants = [
    canonicalRoleName("ThreatIntelligenceCommander"),
    canonicalRoleName("STIX_EvidenceSpecialist"),
    canonicalRoleName("TARA_analyst"),
  ];

  return {
    schema_version: RESULT_SCHEMA_VERSION,
    run_id: input.run_context.run_id,
    generated_at: input.run_context.created_at,
    event: {
      event_id: event.event_id,
      source: event.source,
      event_type: event.event_type,
      triggered_at: event.triggered_at,
      summary: event.summary,
      entity: event.entity,
      observables: event.observables,
      labels: event.labels || [],
      severity: event.severity || null,
    },
    key_information_summary: [
      event.summary,
      `STIX semantic queries returned ${evidenceMatchCount} object matches and ${relationshipCount} related relationship views.`,
      commanderOutput.final_assessment.summary,
    ],
    analysis_conclusion: {
      summary: commanderOutput.final_assessment.summary,
      confidence: commanderOutput.final_assessment.confidence,
      verdict: commanderOutput.final_assessment.verdict,
      supporting_entities: commanderOutput.final_assessment.supporting_entities,
    },
    evidence_query_basis: evidenceBundle,
    recommended_actions: commanderOutput.final_assessment.recommended_actions,
    collaboration_trace: {
      participants,
      legacy_participants: ["ThreatIntelligenceCommander", "STIX_EvidenceSpecialist", "TARA_analyst"],
      role_outputs: [
        { role: evidenceOutput.role, legacy_role: evidenceOutput.legacy_role, summary: evidenceOutput.findings[0] },
        { role: riskOutput.role, legacy_role: riskOutput.legacy_role, summary: riskOutput.findings[0] },
        { role: commanderOutput.role, legacy_role: commanderOutput.legacy_role, summary: commanderOutput.findings[0] },
      ],
      traceability: {
        event_id: event.event_id,
        assembled_by: canonicalRoleName("ThreatIntelligenceCommander"),
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
      },
      assembly_contract: {
        schema: "TASK-009",
        assembled_by: canonicalRoleName("ThreatIntelligenceCommander"),
        assembly_location: "remote-primary",
        contract_source: "services/result_assembler",
      },
    },
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

    if (input.request_contract_version === "threat-intelligence-agent.remote-request.v2" && input.event && input.run_context) {
      const output = buildStructuredResult(input, workspaceRoot);

      context.metadata({
        title: "threat_intel_orchestrator",
        metadata: {
          participants: output.collaboration_trace.participants,
          mode: "structured_result",
        },
      });

      return JSON.stringify(output, null, 2);
    }

    const evidenceOutput = evidenceSpecialist(input, workspaceRoot);
    const riskOutput = taraAnalyst(input, evidenceOutput, workspaceRoot);
    const commanderOutput = commander(input, evidenceOutput, riskOutput, workspaceRoot);

    const output = {
      run_id: input.run_context.run_id,
      participants: [
        canonicalRoleName("ThreatIntelligenceCommander"),
        canonicalRoleName("STIX_EvidenceSpecialist"),
        canonicalRoleName("TARA_analyst"),
      ],
      legacy_participants: ["ThreatIntelligenceCommander", "STIX_EvidenceSpecialist", "TARA_analyst"],
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
        assembled_by: canonicalRoleName("ThreatIntelligenceCommander"),
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
