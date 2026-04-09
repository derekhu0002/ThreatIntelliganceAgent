#!/usr/bin/env node
// @ArchitectureID: ELM-APP-COMP-AGENT-ORCH

const fs = require("fs");
const path = require("path");

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function readAgentDefinition(relativePath) {
  const absolutePath = path.resolve(__dirname, "..", relativePath);
  return {
    path: relativePath,
    preview: fs.readFileSync(absolutePath, "utf8").split("\n").slice(0, 8).join("\n")
  };
}

function flattenMatches(bundle) {
  return (bundle.searches || []).flatMap((search) => search.matches || []);
}

function evidenceSpecialist(input) {
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
    role: "STIX_EvidenceSpecialist",
    responsibility: "Correlate the pushed event with local STIX entities and relationships.",
    findings: [
      `Matched entities: ${namedMatches.join(", ") || "none"}.`,
      `Related peer entities: ${relatedPeers.join(", ") || "none"}.`,
      `Observed relationship types: ${relationshipTypes.join(", ") || "none"}.`,
      averageConfidence !== null ? `Average confidence across matched STIX objects: ${averageConfidence}.` : "No explicit confidence score was present in matched STIX objects."
    ],
    supporting_evidence_refs: matches.slice(0, 4).map((match) => match.id),
    definition_source: readAgentDefinition("agents/STIX_EvidenceSpecialist.md")
  };
}

function taraAnalyst(input, evidenceOutput) {
  const evidenceText = evidenceOutput.findings.join(" ");
  const mentionsActor = /APT28/i.test(evidenceText);
  const mentionsPhishing = /Spearphishing|phishing/i.test(`${input.event.summary} ${evidenceText}`);
  const severity = String(input.event.severity || "medium").toLowerCase();

  const confidence = mentionsActor ? "high" : severity === "high" ? "medium-high" : "medium";
  const verdict = mentionsActor ? "likely-known-threat-activity" : "suspicious-activity-needs-hunt";
  const recommendations = [
    "Block or monitor the indicator and associated IP infrastructure in network controls.",
    "Hunt for related authentication, email, and outbound-connection telemetry tied to the observable.",
    "Review users or assets exposed to phishing delivery paths and reset affected credentials if needed."
  ];
  if (mentionsActor || mentionsPhishing) {
    recommendations.push("Pivot on actor-linked malware and phishing techniques in endpoint and email detections.");
  }

  return {
    role: "TARA_analyst",
    responsibility: "Assess likely threat significance, impact, and recommended actions.",
    findings: [
      `Risk verdict: ${verdict}.`,
      `Assessment confidence: ${confidence}.`,
      mentionsPhishing ? "Delivery and post-compromise tradecraft are consistent with phishing-driven credential access." : "The available data indicates suspicious infrastructure activity that still requires broader hunting."
    ],
    recommended_actions: recommendations,
    verdict,
    confidence,
    definition_source: readAgentDefinition("agents/TARA_analyst.md")
  };
}

function commander(input, evidenceOutput, riskOutput) {
  const supportingEntities = [
    ...new Set([
      ...flattenMatches(input.evidence_bundle).map((match) => match.name).filter(Boolean),
      ...(input.evidence_bundle.relationships || []).flatMap((view) => (view.relationships || []).map((item) => item.peer && item.peer.name).filter(Boolean))
    ])
  ];
  return {
    role: "ThreatIntelliganceCommander",
    responsibility: "Synthesize specialist findings into the final structured threat-intelligence assessment.",
    findings: [
      `Event ${input.event.event_id} from ${input.event.source} was correlated with ${supportingEntities.length} relevant STIX entities.`,
      evidenceOutput.findings[0],
      riskOutput.findings[0]
    ],
    final_assessment: {
      summary: supportingEntities.includes("APT28")
        ? "The pushed indicator aligns with known APT28-linked phishing activity and warrants rapid containment plus targeted hunting."
        : "The pushed indicator is suspicious and should be investigated with targeted hunting based on the matched local STIX evidence.",
      confidence: riskOutput.confidence,
      verdict: riskOutput.verdict,
      recommended_actions: riskOutput.recommended_actions,
      supporting_entities: supportingEntities
    },
    definition_source: readAgentDefinition("agents/ThreatIntelliganceCommander.md")
  };
}

function main() {
  const inputPath = process.argv[2];
  if (!inputPath) {
    throw new Error("Usage: node threat_intel_orchestrator.js <input.json>");
  }

  const input = readJson(inputPath);
  const evidenceOutput = evidenceSpecialist(input);
  const riskOutput = taraAnalyst(input, evidenceOutput);
  const commanderOutput = commander(input, evidenceOutput, riskOutput);

  const output = {
    run_id: input.run_context.run_id,
    participants: ["ThreatIntelliganceCommander", "STIX_EvidenceSpecialist", "TARA_analyst"],
    role_outputs: [evidenceOutput, riskOutput, commanderOutput],
    final_assessment: commanderOutput.final_assessment,
    traceability: {
      evidence_refs: [...new Set([...(evidenceOutput.supporting_evidence_refs || [])])],
      definition_sources: [
        evidenceOutput.definition_source.path,
        riskOutput.definition_source.path,
        commanderOutput.definition_source.path
      ]
    }
  };

  process.stdout.write(JSON.stringify(output, null, 2));
}

main();
