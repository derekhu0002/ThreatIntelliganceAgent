const fs = require('fs');
const path = require('path');

const repoRoot = path.resolve(__dirname, '..', '..', '..');

const HANDOFFS = {
    'intent-to-implementation': {
        filePath: 'design/KG/IntentToImplementationHandoff.json',
        schemaPath: '.github/argoschema/IntentToImplementationHandoff.schema.json',
        validate: validateIntentToImplementation,
    },
    'implementation-to-coding': {
        filePath: 'design/KG/ImplementationToCodingHandoff.json',
        schemaPath: '.github/argoschema/ImplementationToCodingHandoff.schema.json',
        validate: validateImplementationToCoding,
    },
};

function main() {
    const stage = process.argv[2];
    const stages = stage ? [stage] : Object.keys(HANDOFFS);
    const errors = [];

    for (const currentStage of stages) {
        const config = HANDOFFS[currentStage];
        if (!config) {
            errors.push(`Unknown stage '${currentStage}'. Expected one of: ${Object.keys(HANDOFFS).join(', ')}`);
            continue;
        }
        validateStage(currentStage, config, errors);
    }

    if (errors.length > 0) {
        console.error('Stage handoff validation failed:');
        for (const error of errors) {
            console.error(`- ${error}`);
        }
        process.exit(1);
    }

    console.log(`Stage handoff validation passed for: ${stages.join(', ')}`);
}

function validateStage(stage, config, errors) {
    const handoffAbsolutePath = path.join(repoRoot, config.filePath);
    const schemaAbsolutePath = path.join(repoRoot, config.schemaPath);

    if (!fs.existsSync(schemaAbsolutePath)) {
        errors.push(`${stage}: schema file is missing at ${config.schemaPath}`);
        return;
    }

    if (!fs.existsSync(handoffAbsolutePath)) {
        errors.push(`${stage}: handoff file is missing at ${config.filePath}`);
        return;
    }

    let document;
    try {
        document = JSON.parse(fs.readFileSync(handoffAbsolutePath, 'utf8'));
    } catch (error) {
        errors.push(`${stage}: failed to parse ${config.filePath}: ${String(error)}`);
        return;
    }

    config.validate(document, errors, config.filePath);
}

function validateIntentToImplementation(document, errors, filePath) {
    requireString(document, 'stage', errors, filePath);
    requireString(document, 'generatedAt', errors, filePath);
    requireString(document, 'sourceIntentGraphPath', errors, filePath);
    requireStringArray(document, 'intentElementIds', true, errors, filePath);
    requireStringArray(document, 'frozenBaselines', true, errors, filePath);
    requireStringArray(document, 'requiredImplementationArtifacts', true, errors, filePath);

    const graphPath = requireString(document, 'sourceIntentGraphPath', errors, filePath);
    if (graphPath) {
        ensureRepoPathExists(graphPath, `${filePath}.sourceIntentGraphPath`, errors);
    }

    const testcases = requireArray(document, 'explicitTestcases', true, errors, filePath);
    if (Array.isArray(testcases)) {
        testcases.forEach((testcase, index) => {
            requireString(testcase, 'name', errors, `${filePath}.explicitTestcases[${index}]`);
            requireString(testcase, 'mountedElementId', errors, `${filePath}.explicitTestcases[${index}]`);
            requireString(testcase, 'type', errors, `${filePath}.explicitTestcases[${index}]`);
            requireString(testcase, 'controlPoint', errors, `${filePath}.explicitTestcases[${index}]`);
            requireString(testcase, 'observationPoint', errors, `${filePath}.explicitTestcases[${index}]`);
            requireString(testcase, 'acceptanceBoundary', errors, `${filePath}.explicitTestcases[${index}]`);
            const entryKind = requireString(testcase, 'requiredEntryKind', errors, `${filePath}.explicitTestcases[${index}]`);
            if (entryKind && !['explicit-testcase-entry', 'read-only-contract-update', 'critical-non-explicit-test'].includes(entryKind)) {
                errors.push(`${filePath}.explicitTestcases[${index}].requiredEntryKind must be one of explicit-testcase-entry, read-only-contract-update, critical-non-explicit-test`);
            }
        });
    }

    const questions = document.openQuestions;
    if (Array.isArray(questions)) {
        questions.forEach((question, index) => {
            requireString(question, 'question', errors, `${filePath}.openQuestions[${index}]`);
            requireString(question, 'recommendedAnswer', errors, `${filePath}.openQuestions[${index}]`);
            requireString(question, 'reason', errors, `${filePath}.openQuestions[${index}]`);
        });
    }
}

function validateImplementationToCoding(document, errors, filePath) {
    requireString(document, 'stage', errors, filePath);
    requireString(document, 'generatedAt', errors, filePath);
    const graphPath = requireString(document, 'sourceIntentGraphPath', errors, filePath);
    if (graphPath) {
        ensureRepoPathExists(graphPath, `${filePath}.sourceIntentGraphPath`, errors);
    }

    const implementationContracts = requireStringArray(document, 'implementationContracts', true, errors, filePath);
    if (Array.isArray(implementationContracts)) {
        implementationContracts.forEach((contractPath, index) => {
            ensureRepoPathExists(contractPath, `${filePath}.implementationContracts[${index}]`, errors);
        });
    }

    const explicitEntrypoints = requireArray(document, 'explicitEntrypoints', true, errors, filePath);
    if (Array.isArray(explicitEntrypoints)) {
        explicitEntrypoints.forEach((entry, index) => {
            requireString(entry, 'testcaseName', errors, `${filePath}.explicitEntrypoints[${index}]`);
            const entryPath = requireString(entry, 'entryPath', errors, `${filePath}.explicitEntrypoints[${index}]`);
            requireString(entry, 'controlPoint', errors, `${filePath}.explicitEntrypoints[${index}]`);
            requireString(entry, 'observationPoint', errors, `${filePath}.explicitEntrypoints[${index}]`);
            const status = requireString(entry, 'initialExecutionStatus', errors, `${filePath}.explicitEntrypoints[${index}]`);
            requireString(entry, 'initialExecutionCommand', errors, `${filePath}.explicitEntrypoints[${index}]`);
            if (entryPath) {
                ensureRepoPathExists(entryPath, `${filePath}.explicitEntrypoints[${index}].entryPath`, errors);
            }
            if (status && !['passed', 'failed'].includes(status)) {
                errors.push(`${filePath}.explicitEntrypoints[${index}].initialExecutionStatus must be 'passed' or 'failed'`);
            }
            if (status === 'failed') {
                requireString(entry, 'failureReason', errors, `${filePath}.explicitEntrypoints[${index}]`);
            }
        });
    }

    const criticalTests = requireArray(document, 'criticalNonExplicitTests', false, errors, filePath) || [];
    criticalTests.forEach((test, index) => validateNonExplicitTest(test, `${filePath}.criticalNonExplicitTests[${index}]`, errors));

    const supportingTests = requireArray(document, 'supportingNonExplicitTests', false, errors, filePath) || [];
    supportingTests.forEach((test, index) => validateNonExplicitTest(test, `${filePath}.supportingNonExplicitTests[${index}]`, errors));

    const failureRecordsPath = requireString(document, 'expectedFailureRecordsPath', errors, filePath);
    if (failureRecordsPath) {
        ensureRepoPathExists(failureRecordsPath, `${filePath}.expectedFailureRecordsPath`, errors);
    }

    const codingTargets = requireArray(document, 'codingTargets', true, errors, filePath);
    if (Array.isArray(codingTargets)) {
        codingTargets.forEach((target, index) => {
            requireString(target, 'failureSignal', errors, `${filePath}.codingTargets[${index}]`);
            requireString(target, 'nextAction', errors, `${filePath}.codingTargets[${index}]`);
        });
    }

    const frozenFiles = requireStringArray(document, 'frozenFiles', true, errors, filePath);
    if (Array.isArray(frozenFiles)) {
        frozenFiles.forEach((frozenFile, index) => {
            ensureRepoPathExists(frozenFile, `${filePath}.frozenFiles[${index}]`, errors);
        });
    }
}

function validateNonExplicitTest(test, prefix, errors) {
    const testPath = requireString(test, 'path', errors, prefix);
    requireString(test, 'controlPoint', errors, prefix);
    requireString(test, 'observationPoint', errors, prefix);
    if (testPath) {
        ensureRepoPathExists(testPath, `${prefix}.path`, errors);
    }
}

function requireString(object, key, errors, prefix) {
    if (!object || typeof object[key] !== 'string' || object[key].trim() === '') {
        errors.push(`${prefix}.${key} must be a non-empty string`);
        return undefined;
    }
    return object[key];
}

function requireArray(object, key, mustHaveItems, errors, prefix) {
    if (!object || !Array.isArray(object[key])) {
        errors.push(`${prefix}.${key} must be an array`);
        return undefined;
    }
    if (mustHaveItems && object[key].length === 0) {
        errors.push(`${prefix}.${key} must not be empty`);
    }
    return object[key];
}

function requireStringArray(object, key, mustHaveItems, errors, prefix) {
    const value = requireArray(object, key, mustHaveItems, errors, prefix);
    if (!Array.isArray(value)) {
        return undefined;
    }
    value.forEach((entry, index) => {
        if (typeof entry !== 'string' || entry.trim() === '') {
            errors.push(`${prefix}.${key}[${index}] must be a non-empty string`);
        }
    });
    return value;
}

function ensureRepoPathExists(relativePath, label, errors) {
    const normalized = relativePath.replace(/[\\/]+/g, path.sep);
    const absolutePath = path.join(repoRoot, normalized);
    if (!fs.existsSync(absolutePath)) {
        errors.push(`${label} points to a missing path: ${relativePath}`);
    }
}

main();