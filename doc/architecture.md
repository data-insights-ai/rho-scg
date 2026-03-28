# Architecture

## Overview

SCG is a Go CLI that models CI/CD dependencies as a temporal knowledge graph. The graph is the engine; the user interface is a simple CLI. Users never need to know about the graph — it powers the analysis invisibly.

```
User Interface        scg init | check | scope | audit
                           |
Logic Layer           parser/ -> resolver/ -> manifest/ -> scoper/
                           |
Graph Engine          TKG v3 (graph/) + Cypher (queries/)
                           |
Storage               MemoryStore (CLI) | BadgerStore (daemon)
```

## Core Design Decisions

### 1. Dependencies Are a Graph

CI/CD dependencies have natural graph structure:
- **Nodes**: tools, digests, steps, secrets, pipelines, profiles
- **Edges**: "resolves to", "uses", "has access to", "forbids"
- **Time**: resolutions change over time (tags get hijacked)

Modeling this as a graph enables queries that flat data structures can't support efficiently: blast radius analysis, transitive dependency chains, and temporal drift detection.

### 2. Temporal Edges for Drift Detection

The `RESOLVES_TO` relationship between Tool and Digest nodes carries temporal validity:

```
Time ────────────────────────────────────────────────>

Tool "trivy-action@v1"
  |── RESOLVES_TO ──> Digest "sha256:57a9..."
  |   ValidFrom: Jan 1    ValidTo: Mar 15 (attack!)
  |
  └── RESOLVES_TO ──> Digest "sha256:ff00..."
      ValidFrom: Mar 15   ValidTo: (open)
```

Drift detection becomes a temporal query: "what was this tool resolving to when we locked it, vs. what does it resolve to now?" If different, it's drift. If the version didn't change but the digest did, it's a tag hijack.

### 3. Graph Is Invisible

Users interact with:
- `scg.lock` — a human-readable JSON lockfile (committed to git)
- CLI commands — `scg init`, `scg check`, `scg scope`
- Exit codes — 0 (clean) or 1 (drift/violations)

The graph is an internal implementation detail. The lockfile is the portable artifact.

### 4. Two Independent Defense Layers

```
Layer 1: Manifest Enforcement
  "Is this dependency the same binary we approved?"
  Detects: tag hijacking, typosquatting, dependency confusion

Layer 2: Secret Scoping
  "Does this tool need access to this secret?"
  Prevents: credential theft, lateral movement, privilege escalation
```

Either layer alone breaks a supply chain attack. Together, they make it structurally impossible.

## Graph Schema

### Node Labels

| Label | Properties | Purpose |
|---|---|---|
| `Tool` | ecosystem, reference, name, owner | A CI/CD dependency |
| `Digest` | hash, algorithm, source | An immutable content hash |
| `Step` | name, workflow, job | A CI pipeline step |
| `Secret` | name, source, category | An environment variable or credential |
| `Pipeline` | path, type, repo | A CI/CD pipeline definition |
| `Profile` | risk_tier, version, audited_by | A tool's security profile |
| `SecretPattern` | regex, reason | A forbidden secret pattern |

### Relationship Types

| Type | From -> To | Temporal? | Purpose |
|---|---|---|---|
| `RESOLVES_TO` | Tool -> Digest | Yes | Resolution with ValidFrom/ValidTo |
| `USES` | Step -> Tool | No | Step depends on tool |
| `HAS_ACCESS` | Step -> Secret | No | Step can read secret |
| `HAS_PROFILE` | Tool -> Profile | No | Tool has security profile |
| `REQUIRES` | Profile -> Secret | No | Tool legitimately needs secret |
| `FORBIDS` | Profile -> SecretPattern | No | Tool must not see matching secrets |
| `CONTAINS_STEP` | Pipeline -> Step | No | Pipeline contains step |

### Key Queries

**Drift detection** — find tools whose digest changed:
```cypher
MATCH (t:Tool {reference: $ref})-[r:RESOLVES_TO]->(d:Digest)
WHERE r.tkg_valid_to = 0
RETURN d.hash
```

**Secret violations** — find exposed secrets that should be blocked:
```cypher
MATCH (s:Step {name: $step})-[:USES]->(t:Tool)-[:HAS_PROFILE]->(p:Profile)
      -[:FORBIDS]->(pat:SecretPattern)
MATCH (s)-[:HAS_ACCESS]->(sec:Secret)
WHERE sec.name =~ pat.regex
RETURN sec.name, pat.reason, t.reference
```

**Blast radius** — what's affected if a tool is compromised:
```cypher
MATCH (t:Tool {reference: $ref})
RETURN t
DEPTH 3
```

## Package Structure

```
cmd/scg/          CLI entry point — dispatches to subcommands
graph/            TKG schema, store factory, Cypher query constants
resolver/         Resolve mutable refs -> immutable digests
  resolver.go     Interface: Resolver, Resolution, Ecosystem
  github.go       GitHub Actions: tag -> commit SHA via API
parser/           Extract refs from CI/CD config files
  parser.go       Interface: Parser, ToolRef, SecretRef, WorkflowFile
  workflow.go     GitHub Actions YAML parser
manifest/         Lockfile lifecycle
  manifest.go     Data model: Lockfile, ToolEntry, Signature
  lock.go         Read/write scg.lock (JSON)
  sign.go         Ed25519 signing + OIDC keyless (future)
  drift.go        Compare locked vs. live digests
scoper/           Secret access policy engine
  scoper.go       Cypher-based policy evaluation
  env.go          Environment variable scanning
dsm/              Dependency Security Model
  embedded.go     Built-in profiles for top CI tools
  client.go       Platform API client (paid tier)
platform/         SCG Platform API types and client
internal/config/  Configuration from environment
internal/testutil Test helpers
```

## Data Flow

### `scg init`

```
1. Discover workflow files (parser/)
2. Parse each file -> ToolRef[], SecretRef[], StepDef[]
3. Create in-memory graph (graph/)
4. Bootstrap DSM profiles into graph (dsm/)
5. For each ToolRef:
   a. Resolve reference -> digest (resolver/)
   b. Create Tool, Digest nodes
   c. Create RESOLVES_TO relationship (temporal)
6. Create Step, Secret, Pipeline nodes
7. Create USES, HAS_ACCESS, CONTAINS_STEP relationships
8. Create property indexes
9. Project graph state -> Lockfile
10. Sign and write scg.lock
```

### `scg check`

```
1. Read scg.lock
2. Verify signature
3. For each ToolEntry in lockfile:
   a. Re-resolve reference -> live digest (resolver/)
   b. Compare live digest vs. locked digest
   c. If different: CRITICAL drift (possible tag hijack)
4. Report results
5. Exit 0 (clean) or 1 (drift)
```

### `scg scope`

```
1. Create in-memory graph
2. Bootstrap DSM profiles
3. Scan environment for secret-like variables (scoper/env.go)
4. Populate Secret nodes in graph
5. Execute QuerySecretViolations Cypher query
6. Report violations (which secrets should be stripped)
7. Optionally: unset forbidden env vars
```

## Storage Backends

| Backend | Use Case | Persistence | Performance |
|---|---|---|---|
| MemoryStore | CLI mode (default) | None — ephemeral per run | Fastest |
| BadgerStore | Daemon mode | Disk-backed, survives restarts | Fast reads, async writes |
| TieredStore | Platform (future) | Sharded hot/warm/cold | Scales to millions |

The storage backend is selected by configuration, not code changes. All queries work identically across backends.

## Signing Model

### Ed25519 (default, air-gapped environments)

```
Generate keypair -> sign lockfile content -> embed signature + public key in scg.lock
Verify: check ed25519 signature against embedded public key
```

### OIDC Keyless (CI environments, planned)

```
1. Get OIDC token from CI provider (GitHub Actions, GitLab, etc.)
2. Generate ephemeral ed25519 keypair
3. Sign lockfile with ephemeral key
4. Embed: signature + ephemeral public key + OIDC claims
5. Verify: validate OIDC token via JWKS -> verify ed25519 signature
```

No long-lived keys to manage. The CI identity proves who signed.

## Future: Tyla Temporal Reasoning

The [Tyla engine](https://gitlab2024.bds421-cloud.com/bds421/sigma/tkgd) enables declarative security policies:

```prolog
% Transitive dependency risk
at_risk(T) :- resolves(T, D1), resolves(T, D2), D1 \= D2.
at_risk(T) :- depends(T, Dep), at_risk(Dep).

% Tool stable for 30 days (box past operator)
[]_[0, 2592000000] stable(T) :- resolves(T, D).

% Recent drift (diamond past operator)
<>_[0, 86400000] recent_drift(T) :- at_risk(T).
```

Security teams write rules, not Go code. SCG evaluates them against the live graph.
