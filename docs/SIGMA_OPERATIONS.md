# Sigma Engine Operations & Maintenance

## Operational Guidelines

1. **Rule Lifecycle Management**:
   - `DRAFT` -> `VALIDATED` -> `ENABLED` / `DISABLED`
   - Only `ENABLED` rules participate in live production event evaluation.

2. **Deduplication Safeguards**:
   - Matches triggered by identical rule ID and source IP within a 10-minute sliding window are deduplicated to prevent SOC alert fatigue.

3. **Role-Based Access Control (RBAC)**:
   - `VIEWER`: View rules, field mappings, validation status, and execution stats.
   - `ANALYST`: Import rules, validate YAML, run sandbox tests, toggle enable/disable state.
   - `ADMIN`: Full management, rule deletion, global configuration.

4. **Performance Safeguards**:
   - Production evaluation operates asynchronously in background threads.
   - Database queries are indexed by `rule_id`, `enabled`, `status`, `event_id`, and `created_at`.
