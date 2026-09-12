# Sigma Rule Import & Validation Workflow

## Overview

NetWatch supports importing single-document and multi-document Sigma YAML rules. All imports undergo strict security validation before storage or activation.

## Import Guidelines

- **File Formats**: `.yaml`, `.yml`
- **Maximum File Size**: 1 MB (`NETWATCH_SIGMA_MAX_RULE_SIZE_MB`)
- **Safe Parsing**: Uses PyYAML `yaml.safe_load` to prevent arbitrary code execution or YAML bombs.

## Validation Statuses

1. `VALID`: Rule contains all required headers (`title`, `logsource`, `detection`, `condition`) and all fields map to supported NetWatch attributes.
2. `UNSUPPORTED`: Rule contains valid YAML and syntax, but includes field names not present in the NetWatch telemetry schema.
3. `INVALID`: Rule contains malformed YAML, missing required fields, or syntax errors.
4. `DUPLICATE`: Rule ID already exists in the database.

## Rule Activation Policy

Only `VALID` rules can be toggled to `ENABLED` status. Imported rules default to `DISABLED` state upon import to prevent accidental alert generation.
