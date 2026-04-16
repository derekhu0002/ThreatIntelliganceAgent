// @ArchitectureID: ELM-APP-COMP-SCHEMA-EXPLORER
// @ArchitectureID: ELM-APP-FUNC-PUBLISH-SEMANTIC-SCHEMA-MENU

import { existsSync, readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { tool } from "@opencode-ai/plugin";
import { z } from "zod";

const FILE_DIR = path.dirname(fileURLToPath(import.meta.url));
const LOCAL_WORKSPACE_ROOT = path.resolve(FILE_DIR, "..", "..");
const ANALYST_AGENTS = new Set(["ThreatIntelAnalyst", "STIX_EvidenceSpecialist"]);
const SECOPS_AGENTS = new Set(["ThreatIntelSecOps", "TARA_analyst"]);
const SCHEMA_DIRECTORIES = {
  entities: ["sdos", "observables"],
  relationships: ["sros"],
};
const RELATIONSHIP_SELECTOR_FIELDS = ["relationship_type", "source_ref", "target_ref", "where_sighted_refs", "sighting_of_ref"];
const nonEmptyString = z.string().trim().min(1);
const propertyOptionSchema = z.object({
  name: nonEmptyString,
  type: nonEmptyString,
  description: z.string().nullable(),
  required: z.boolean(),
  source: nonEmptyString,
}).strict();
const relationshipOptionSchema = z.object({
  name: nonEmptyString,
  title: nonEmptyString,
  schema_file: nonEmptyString,
  selector_fields: z.array(nonEmptyString),
  required_fields: z.array(nonEmptyString),
}).strict();
const entityMenuItemSchema = z.object({
  entity_type: nonEmptyString,
  title: nonEmptyString,
  schema_file: nonEmptyString,
  required_properties: z.array(nonEmptyString),
  property_options: z.array(propertyOptionSchema),
  relationship_options: z.array(relationshipOptionSchema),
}).strict();
const schemaMenuSchema = z.object({
  schema_version: nonEmptyString,
  schema_first_guidance: nonEmptyString,
  schema_authority: z.object({
    root: nonEmptyString,
    source: nonEmptyString,
    bundle_summary_authority: nonEmptyString,
    files_loaded: z.number().int().positive(),
  }).strict(),
  supported_query_fields: z.array(nonEmptyString),
  relationship_fields: z.array(nonEmptyString),
  entity_types: z.array(z.object({
    entity_type: nonEmptyString,
    key_fields: z.array(nonEmptyString),
    relationship_types: z.array(nonEmptyString),
  }).strict()),
  menu: z.object({
    common_properties: z.array(propertyOptionSchema),
    entities: z.array(entityMenuItemSchema),
    relationships: z.array(relationshipOptionSchema),
  }).strict(),
}).strict();

function resolveWorkspaceRoot(context) {
  const candidates = [
    context.directory,
    process.env.THREAT_INTEL_WORKSPACE_ROOT,
    LOCAL_WORKSPACE_ROOT,
    context.worktree && path.resolve(context.worktree, "agent_app", "opencode_app"),
    process.env.THREAT_INTEL_REPO_ROOT && path.resolve(process.env.THREAT_INTEL_REPO_ROOT, "agent_app", "opencode_app"),
  ];

  for (const candidate of candidates) {
    if (!candidate) {
      continue;
    }

    const normalized = path.resolve(candidate);
    if (existsSync(path.join(normalized, ".opencode", "schema"))) {
      return normalized;
    }
  }

  return LOCAL_WORKSPACE_ROOT;
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
    "ThreatIntelSecOps must use the analyst-provided threat-intelligence evidence already returned by ThreatIntelPrimary.",
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

  throw new Error(
    `db_schema_explorer is restricted to ThreatIntelAnalyst compatibility scope; received agent ${agentName || "<unset>"}.`,
  );
}

function readJson(filePath) {
  return JSON.parse(readFileSync(filePath, "utf8"));
}

function walkJsonFiles(rootDirectory) {
  const results = [];
  const stack = [rootDirectory];

  while (stack.length > 0) {
    const current = stack.pop();
    for (const entry of readdirSync(current, { withFileTypes: true })) {
      const absolutePath = path.join(current, entry.name);
      if (entry.isDirectory()) {
        stack.push(absolutePath);
        continue;
      }
      if (entry.isFile() && absolutePath.endsWith(".json")) {
        results.push(absolutePath);
      }
    }
  }

  return results.sort();
}

function pointerLookup(document, pointer) {
  if (!pointer || pointer === "#") {
    return document;
  }

  return pointer
    .replace(/^#\//, "")
    .split("/")
    .filter(Boolean)
    .reduce((current, segment) => current?.[segment.replace(/~1/g, "/").replace(/~0/g, "~")], document);
}

function resolveReferencedNode(ref, currentFilePath, cache) {
  const refText = String(ref);
  const hashIndex = refText.indexOf("#");
  const relativeTarget = hashIndex >= 0 ? refText.slice(0, hashIndex) : refText;
  const pointer = hashIndex >= 0 ? refText.slice(hashIndex) : "#";
  const targetPath = relativeTarget
    ? path.resolve(path.dirname(currentFilePath), relativeTarget)
    : currentFilePath;
  const document = loadSchemaDocument(targetPath, cache);
  return {
    filePath: targetPath,
    node: pointerLookup(document, pointer || "#"),
  };
}

function loadSchemaDocument(filePath, cache) {
  if (!cache.has(filePath)) {
    cache.set(filePath, readJson(filePath));
  }
  return cache.get(filePath);
}

function describePropertyType(definition) {
  if (!definition || typeof definition !== "object") {
    return "unknown";
  }

  if (typeof definition.type === "string") {
    if (definition.type === "array") {
      return `array<${describePropertyType(definition.items)}>`;
    }
    return definition.type;
  }

  if (Array.isArray(definition.type) && definition.type.length > 0) {
    return definition.type.join("|");
  }

  if (Array.isArray(definition.enum) && definition.enum.length > 0) {
    return `enum(${definition.enum.slice(0, 5).map(String).join(", ")}${definition.enum.length > 5 ? ", ..." : ""})`;
  }

  if (definition.items) {
    return `array<${describePropertyType(definition.items)}>`;
  }

  if (definition.$ref) {
    return `ref:${definition.$ref}`;
  }

  if (Array.isArray(definition.allOf) && definition.allOf.length > 0) {
    return definition.allOf.map((item) => describePropertyType(item)).filter(Boolean).join(" & ") || "object";
  }

  return "object";
}

function mergePropertyOption(existing, next) {
  if (!existing) {
    return next;
  }

  return {
    ...existing,
    ...next,
    description: next.description || existing.description || null,
    type: next.type !== "unknown" ? next.type : existing.type,
    required: existing.required || next.required,
  };
}

function collectSchemaDetails(node, currentFilePath, cache, propertyMap, requiredSet, visitedRefs) {
  if (!node || typeof node !== "object") {
    return;
  }

  if (node.$ref && typeof node.$ref === "string") {
    const visitKey = `${currentFilePath}::${node.$ref}`;
    if (visitedRefs.has(visitKey)) {
      return;
    }
    visitedRefs.add(visitKey);

    const resolved = resolveReferencedNode(node.$ref, currentFilePath, cache);
    collectSchemaDetails(resolved.node, resolved.filePath, cache, propertyMap, requiredSet, visitedRefs);
  }

  if (Array.isArray(node.required)) {
    for (const propertyName of node.required) {
      requiredSet.add(String(propertyName));
    }
  }

  if (node.properties && typeof node.properties === "object") {
    for (const [propertyName, definition] of Object.entries(node.properties)) {
      propertyMap.set(
        propertyName,
        mergePropertyOption(propertyMap.get(propertyName), {
          name: propertyName,
          type: describePropertyType(definition),
          description: definition && typeof definition === "object" && typeof definition.description === "string"
            ? definition.description
            : null,
          required: requiredSet.has(propertyName),
          source: path.basename(currentFilePath),
        }),
      );
    }
  }

  for (const key of ["allOf", "anyOf", "oneOf"]) {
    if (Array.isArray(node[key])) {
      for (const item of node[key]) {
        collectSchemaDetails(item, currentFilePath, cache, propertyMap, requiredSet, visitedRefs);
      }
    }
  }
}

function buildPropertyOptions(schemaFilePath, cache) {
  const propertyMap = new Map();
  const requiredSet = new Set();
  const schema = loadSchemaDocument(schemaFilePath, cache);
  collectSchemaDetails(schema, schemaFilePath, cache, propertyMap, requiredSet, new Set());

  const propertyOptions = [...propertyMap.values()]
    .map((item) => ({ ...item, required: requiredSet.has(item.name) || item.required }))
    .sort((left, right) => left.name.localeCompare(right.name));

  return {
    propertyOptions,
    requiredProperties: propertyOptions.filter((item) => item.required).map((item) => item.name),
  };
}

function toRelativeSchemaPath(schemaRoot, filePath) {
  return path.relative(schemaRoot, filePath).split(path.sep).join("/");
}

function buildRelationshipMenu(schemaRoot, cache) {
  const relationshipFiles = SCHEMA_DIRECTORIES.relationships.flatMap((directory) =>
    walkJsonFiles(path.join(schemaRoot, directory)),
  );

  return relationshipFiles.map((filePath) => {
    const schema = loadSchemaDocument(filePath, cache);
    const details = buildPropertyOptions(filePath, cache);
    const selectorFields = details.propertyOptions
      .map((item) => item.name)
      .filter((name) => RELATIONSHIP_SELECTOR_FIELDS.includes(name));

    return {
      name: path.basename(filePath, ".json"),
      title: String(schema.title || path.basename(filePath, ".json")),
      schema_file: toRelativeSchemaPath(schemaRoot, filePath),
      selector_fields: selectorFields,
      required_fields: details.requiredProperties,
    };
  });
}

function buildEntityMenu(schemaRoot, cache, relationshipMenu) {
  const entityFiles = SCHEMA_DIRECTORIES.entities.flatMap((directory) =>
    walkJsonFiles(path.join(schemaRoot, directory)),
  );

  return entityFiles.map((filePath) => {
    const schema = loadSchemaDocument(filePath, cache);
    const details = buildPropertyOptions(filePath, cache);

    return {
      entity_type: path.basename(filePath, ".json"),
      title: String(schema.title || path.basename(filePath, ".json")),
      schema_file: toRelativeSchemaPath(schemaRoot, filePath),
      required_properties: details.requiredProperties,
      property_options: details.propertyOptions,
      relationship_options: relationshipMenu,
    };
  });
}

function buildSemanticSchemaMenu(schemaRoot) {
  const cache = new Map();
  const relationshipMenu = buildRelationshipMenu(schemaRoot, cache);
  const entities = buildEntityMenu(schemaRoot, cache, relationshipMenu);
  const commonCoreDetails = buildPropertyOptions(path.join(schemaRoot, "common", "core.json"), cache);
  const supportedQueryFields = new Set(commonCoreDetails.propertyOptions.map((item) => item.name));

  for (const entity of entities) {
    for (const property of entity.property_options) {
      supportedQueryFields.add(property.name);
    }
  }
  for (const relationship of relationshipMenu) {
    for (const field of relationship.selector_fields) {
      supportedQueryFields.add(field);
    }
  }

  const payload = {
    schema_version: "workspace-semantic-schema-menu.v1",
    schema_first_guidance: "Use this workspace semantic schema menu to select entity, property, and relationship options before constructing Neo4j evidence queries or incident writeback plans.",
    schema_authority: {
      root: schemaRoot,
      source: ".opencode/schema/**",
      bundle_summary_authority: "supplemental-only",
      files_loaded: walkJsonFiles(schemaRoot).length,
    },
    supported_query_fields: [...supportedQueryFields].sort(),
    relationship_fields: [...new Set(relationshipMenu.flatMap((item) => item.selector_fields))].sort(),
    entity_types: entities.map((entity) => ({
      entity_type: entity.entity_type,
      key_fields: entity.property_options.map((item) => item.name),
      relationship_types: entity.relationship_options.map((item) => item.name),
    })),
    menu: {
      common_properties: commonCoreDetails.propertyOptions,
      entities,
      relationships: relationshipMenu,
    },
  };

  const validated = schemaMenuSchema.safeParse(payload);
  if (!validated.success) {
    throw new Error(`db_schema_explorer built an invalid semantic schema menu payload: ${validated.error.message}`);
  }

  return validated.data;
}

export default tool({
  description: "Publish the workspace semantic schema menu for analyst-guided Neo4j workflows.",
  args: {
    data: tool.schema.string().optional(),
    pythonBin: tool.schema.string().optional(),
  },
  async execute(args, context) {
    const scope = enforceAgentScope(context);
    if (scope.handoff) {
      return scope.handoff;
    }

    const workspaceRoot = resolveWorkspaceRoot(context);
    const schemaRoot = path.join(workspaceRoot, ".opencode", "schema");
    if (!existsSync(schemaRoot)) {
      throw new Error(`db_schema_explorer could not locate workspace schema catalog at ${schemaRoot}.`);
    }

    context.metadata({
      title: "db_schema_explorer",
      metadata: {
        agent: scope.agentName,
        workspaceRoot,
        schemaRoot,
        compatibility_bundle_data: args.data || null,
        compatibility_python_bin: args.pythonBin || null,
      },
    });

    return JSON.stringify(buildSemanticSchemaMenu(schemaRoot), null, 2);
  },
});
