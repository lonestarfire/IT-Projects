# Portfolio - Sanitized Automation Projects

This folder contains **sanitized** versions of automation projects (runbooks, Azure Function App, and Logic App definitions) prepared for public GitHub publishing.

All environment-specific values have been removed or replaced with placeholders.

## Placeholder conventions
Replace these placeholders with your own environment values:

- `__SUBSCRIPTION_ID__`
- `__RESOURCE_GROUP__`
- `__AUTOMATION_ACCOUNT__`
- `__AUTOMATION_CONNECTION_NAME__`
- `__TABLE_CONNECTION_NAME__`
- `__KEYVAULT_CONNECTION_NAME__`
- `__STORAGE_TABLE_INCOMING__`
- `__STORAGE_TABLE_THROTTLE__`
- `__WORKER_GROUP_AD__`
- `__WORKER_GROUP_OFFLOAD__`
- `__DOMAIN_PRIMARY__` (example: `example.com`)
- `__DOMAIN_SECONDARY__` (example: `example.org`)
- `__HR_SYSTEM_NAME__`
- `__HR_SYSTEM_API_BASE_URL__`

## Structure
- `FunctionApp/` - Azure Functions (isolated worker) app that ingests webhooks into Azure Table Storage and triggers downstream workflows.
- `LogicApps/` - Logic App workflow definitions (JSON) illustrating orchestration, deduplication, and runbook triggering.
- `Runbooks/` - PowerShell runbooks for directory operations, mail operations, offload orchestration, and retry handling.
- `Scripts/` - Standalone PowerShell utilities (e.g., identity anchor alignment, Box user updates) sanitized for public sharing.

## Security notes
- No secrets are included.
- Any authentication tokens, shared keys, client secrets, tenant IDs, and URIs have been replaced with placeholders.
- The code is provided as a reference architecture. You must supply your own secure configuration (Key Vault / app settings / Automation variables).
