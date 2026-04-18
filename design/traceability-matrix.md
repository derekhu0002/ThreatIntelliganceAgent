# Traceability Matrix

Generated at: 2026-04-18T01:19:33.734Z

| ArchiMate Component | Code Elements | Confidence | Rationale |
|---------------------|---------------|------------|-----------|
| Threat Analysis and Collaboration | ThreatIntelListener, AnalysisConclusion, ThreatAnalysisResult | 90% | The ThreatIntelListener processes events and dispatches analysis requests, while AnalysisConclusion and ThreatAnalysisResult encapsulate analysis outcomes. |
| STIX Data Management | StixObjectSummary, StixSearchResult, StixSchemaSummary, agent_app_opencode_app_tools_stix_cli_semantic_query | 85% | These classes handle STIX object summaries, searches, schema details, and semantic queries, aligning with data management tasks. |
| Remote Server Integration | RemoteOpencodeClient, _MockRemoteServer, MockRemoteServerHandle | 90% | RemoteOpencodeClient manages server communication, while _MockRemoteServer and MockRemoteServerHandle support integration testing. |
| STIX Services | services_stix_contracts_catalog, services_stix_contracts_models | 80% | These classes provide utilities and services for STIX contract management, aligning with the STIX Services component. |
| Threat Intelligence Listener | ThreatIntelListener, services_python_listener___main__ | 90% | ThreatIntelListener processes intelligence events, and services_python_listener___main__ runs the listener flow. |
| Result Assembler | services_result_assembler_assembler, services_result_assembler_schema | 90% | These classes assemble and validate structured analysis results, directly implementing the Result Assembler intent. |
| Remote Client | RemoteOpencodeClient, services_python_listener_remote_client | 85% | RemoteOpencodeClient handles server communication, and services_python_listener_remote_client resolves workspace configurations for remote operations. |
| Mock Server | _MockRemoteServer, services_remote_opencode_server_mock_server | 90% | These classes implement mock server functionality for testing remote interactions. |
| CLI Tools | agent_app_opencode_app_tools_stix_cli___main__, agent_app_opencode_app_tools_stix_cli_semantic_query | 85% | These classes provide CLI tools for executing and processing STIX queries, aligning with the CLI Tools component. |
| Testing Framework | tests_test_stix_contracts, tests_test_result_assembler, tests_test_python_listener, tests_test_mock_opencti_adapter | 80% | These test classes validate the functionality of various components, supporting the Testing Framework intent. |
| Database | agent_app_opencode_app__opencode_tools_db_schema_explorer | 85% | This class explores and processes database schema files, aligning with the Database component. |
| Neo4j | agent_app_opencode_app__opencode_tools_neo4j_query | 85% | This class manages Neo4j query execution, directly implementing the Neo4j component. |
| HTTP Server | _MockRemoteServer, services_remote_opencode_server_mock_server | 90% | These classes implement HTTP server functionality for remote integration testing. |
| CLI Runtime | agent_app_opencode_app_tools_stix_cli___main__, agent_app_opencode_app_tools_stix_cli_semantic_query | 85% | These classes execute CLI commands and process runtime queries, aligning with the CLI Runtime component. |
