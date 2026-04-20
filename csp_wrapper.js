#!/usr/bin/env node
/**
 * Thin wrapper around @google/csp-evaluator.
 *
 * Install the dependency once:
 *   npm install @google/csp-evaluator
 *
 * This script is called automatically by check_headers.py when Node.js is
 * available. Output is a JSON array of findings on stdout.
 *
 * Usage:
 *   node csp_wrapper.js "<csp-header-value>"
 */

const cspString = process.argv[2];
if (!cspString) {
    process.stderr.write('Usage: node csp_wrapper.js "<csp-string>"\n');
    process.exit(1);
}

let CspEvaluator, CspParser;
try {
    ({ CspEvaluator } = require('csp_evaluator/dist/evaluator.js'));
    ({ CspParser } = require('csp_evaluator/dist/parser.js'));
} catch (e) {
    process.stderr.write(
        'Dependency not installed. Run: npm install github:google/csp-evaluator\n' +
        e.message + '\n'
    );
    process.exit(1);
}

try {
    const { Type } = require('csp_evaluator/dist/finding.js');
    const typeNames = Object.fromEntries(
        Object.entries(Type).filter(([k]) => !isNaN(Number(k)))
    );

    const parsed = new CspParser(cspString).csp;
    const findings = new CspEvaluator(parsed).evaluate();

    // Deduplicate: same directive + description should appear only once
    const seen = new Set();
    const output = [];
    for (const f of findings) {
        const key = `${f.directive}|${f.description}`;
        if (seen.has(key)) continue;
        seen.add(key);
        output.push({
            severity:    f.severity    ?? 1,
            directive:   f.directive   ?? '',
            type:        typeNames[f.type] ?? String(f.type ?? ''),
            description: f.description ?? '',
        });
    }

    process.stdout.write(JSON.stringify(output) + '\n');
    process.exit(0);
} catch (e) {
    process.stderr.write(e.message + '\n');
    process.exit(1);
}
