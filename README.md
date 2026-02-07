# static-params

Backend API for static security analysis of npm packages and uploaded files.  
It runs a rules engine that detects risky patterns (obfuscation, dangerous APIs, typosquatting, etc.) and returns a structured risk report.

## Features
- Analyze npm packages by name (registry metadata)
- Analyze uploaded files + package.json
- Tiered analysis: `quick`, `standard`, `deep`, `all`
- Run a single rule by ID
- Risk scoring + findings summary

## Requirements
- Node.js >= 16
- npm >= 8

## Install
```bash
cd /Users/ishitasodhiya/argus-params/static_params/backend
npm install
Run
npm start
Server runs on http://localhost:5050.

API Endpoints
POST /api/analyze
GET /api/analyze/rules
GET /api/rules
POST /api/rules/:ruleId

Examples

1) Analyze all rules (upload mode)
curl -s -X POST http://localhost:5050/api/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "tier":"all",
    "files":[{"path":"index.js","content":"const x=\"QWxhZGRpbjpvcGVuIHNlc2FtZQ==\";"}],
    "packageJson":{"name":"express","version":"1.0.0"}
  }'

2) Analyze quick (static-only)
curl -s -X POST http://localhost:5050/api/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "tier":"quick",
    "files":[{"path":"index.js","content":"console.log(\"hello\")"}],
    "packageJson":{"name":"express","version":"1.0.0"}
  }'

3) Run a single rule (Entropy)
curl -s -X POST http://localhost:5050/api/rules/1 \
  -H "Content-Type: application/json" \
  -d '{
    "files":[{"path":"index.js","content":"const x=\"QWxhZGRpbjpvcGVuIHNlc2FtZQ==\";"}],
    "packageJson":{"name":"demo-pkg","version":"1.0.0"}
  }'

4) List rules
curl -s http://localhost:5050/api/analyze/rules
Notes
Upload mode enriches context by fetching npm metadata using packageJson.name.
If registry calls fail, the analyzer still runs using safe defaults.
Sandbox rule (ID 4) is disabled by default.
Tests (optional)
npm test

If you want it placed in a different path or want to add scr


