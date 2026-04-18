# Symbol Summaries

| Symbol | Stereotype | Business Effect |
|--------|-----------|-----------------|
| StrictContractModel | <<ValueObject>> | Defines a strict data model with validation and serialization rules. |
| EventEntity | <<Entity>> | Represents an event entity with mandatory identification and type fields. |
| EventObservable | <<Entity>> | Represents an observable tied to an event with type and value. |
| NormalizedMockOpenCTIEvent | <<Entity>> | Models a normalized OpenCTI event with metadata, entity, and observables. |
| StixObjectSummary | <<ValueObject>> | Summarizes a STIX object with optional descriptive fields. |
| StixSearchResult | <<ValueObject>> | Represents the result of a STIX object search with validation on match counts. |
| StixNeighborRelationship | <<ValueObject>> | Defines a relationship between STIX objects with directionality. |
| StixNeighborsResult | <<ValueObject>> | Represents STIX object neighbors with validation on relationship counts. |
| StixAdvancedFilterRelationship | <<ValueObject>> | Defines a relationship between STIX objects for advanced filtering. |
| StixAdvancedFilterResult | <<ValueObject>> | Represents advanced filtering results with validation on counts. |
| StixEntitySchemaSummary | <<ValueObject>> | Summarizes schema details for a STIX entity type. |
| StixSchemaSummary | <<ValueObject>> | Summarizes the STIX schema with supported fields and entity types. |
| EvidenceQueryBasis | <<ValueObject>> | Represents the basis for evidence queries with searches and relationships. |
| AnalysisConclusion | <<ValueObject>> | Represents the conclusion of an analysis with a summary and confidence. |
| CollaborationRoleOutput | <<ValueObject>> | Represents the output of a collaboration role with legacy compatibility. |
| AssemblyContract | <<ValueObject>> | Defines a contract schema for assembly tasks. |
| CollaborationTrace | <<ValueObject>> | Represents traceability and collaboration details for an assembly contract. |
| AnalysisResultEvent | <<ValueObject>> | Encapsulates details of an analysis result event. |
| ThreatAnalysisResult | <<ValueObject>> | Holds the result of a threat analysis, including evidence and recommendations. |
| services/stix_contracts/models | <<Utility>> | Provides utilities for parsing and building analysis result schemas. |
| ContractCatalogError | <<Entity>> | Represents an error when resolving contract catalog schemas. |
| services/stix_contracts/catalog | <<Service>> | Manages loading and resolving contract schemas. |
| tests/test_stix_contracts | <<Test>> | Tests schema resolution and validation for STIX contracts. |
| MockRemoteServerHandle | <<ValueObject>> | Represents a handle for interacting with a mock remote server. |
| _MockRemoteServer | <<Adapter>> | Implements a mock HTTP server for testing remote interactions. |
| services/remote_opencode_server/mock_server | <<Service>> | Provides mock server utilities for remote request handling. |
| tests/test_stix_cli | <<Test>> | Tests STIX CLI tools for entity and relationship queries. |
| tests/test_result_assembler | <<Test>> | Tests the assembly of structured results for threat analysis. |
| tests/test_python_listener | <<Test>> | Tests the Python listener for live environment readiness and remote requests. |
| tests/test_opencode_workspace_config | <<Test>> | Tests the configuration of the OpenCode workspace. |
| tests/test_neo4j_query_tool | <<Utility>> | Tests the execution of Neo4j Cypher queries and validates JSON payloads. |
| tests/test_mock_opencti_adapter | <<Utility>> | Tests normalization and validation of mock OpenCTI events. |
| tests/test_minimal_closed_loop_script | <<Utility>> | Tests the execution and output of a minimal closed-loop script. |
| scripts/run_minimal_closed_loop | <<Controller>> | Runs a minimal closed-loop script for event validation and analysis. |
| RemoteDispatchError | <<ValueObject>> | Represents errors during remote server communication. |
| RemoteOpencodeClient | <<Gateway>> | Handles communication with a remote OpenCode server for analysis. |
| services/python_listener/remote_client | <<Utility>> | Loads and resolves workspace configuration for agents. |
| ThreatIntelListener | <<Service>> | Processes events and dispatches analysis requests to a remote server. |
| EventContractError | <<ValueObject>> | Represents errors in the mock OpenCTI event contract. |
| services/mock_opencti_adapter/adapter | <<Adapter>> | Normalizes and validates mock OpenCTI events. |
| services/python_listener/__main__ | <<Controller>> | Runs the Threat Intelligence Agent listener flow. |
| services/result_assembler/schema | <<Utility>> | Builds the JSON schema for analysis results. |
| services/result_assembler/assembler | <<Service>> | Assembles and validates structured analysis results. |
| agent_app/opencode_app/tools/stix_cli/__main__ | <<Controller>> | Provides a CLI for local STIX 2.1 semantic queries. |
| agent_app/opencode_app/tools/stix_cli/semantic_query | <<Service>> | Executes semantic queries and processes STIX data. |
| agent_app/opencode_app/.opencode/tools/stix_query | <<Utility>> | Handles CLI command execution and validates output for agent-specific operations. |
| agent_app/opencode_app/.opencode/tools/neo4j_query | <<Utility>> | Manages Neo4j query execution and ensures writeback summaries. |
| agent_app/opencode_app/.opencode/tools/db_schema_explorer | <<Utility>> | Explores and processes database schema files to build menus and relationships. |
