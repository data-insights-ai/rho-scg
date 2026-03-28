package graph

// Cypher query constants for SCG operations.
// All queries use parameter binding ($param) to prevent injection.

const (
	// QueryCurrentResolution returns the current (active) digest for a tool.
	// Params: $ref (tool reference string)
	QueryCurrentResolution = `MATCH (t:Tool {reference: $ref})-[r:RESOLVES_TO]->(d:Digest)
RETURN t.reference AS reference, t.ecosystem AS ecosystem,
       d.hash AS hash, d.algorithm AS algorithm, d.source AS source`

	// QueryAllResolutions returns all tool-digest pairs with active resolutions.
	QueryAllResolutions = `MATCH (t:Tool)-[r:RESOLVES_TO]->(d:Digest)
RETURN t.reference AS reference, t.ecosystem AS ecosystem,
       d.hash AS hash, d.algorithm AS algorithm`

	// QueryStepTools returns all tools used by a specific step.
	// Params: $step (step name)
	QueryStepTools = `MATCH (s:Step {name: $step})-[:USES]->(t:Tool)
RETURN t.reference AS reference, t.ecosystem AS ecosystem`

	// QueryStepSecrets returns all secrets accessible to a specific step.
	// Params: $step (step name)
	QueryStepSecrets = `MATCH (s:Step {name: $step})-[:HAS_ACCESS]->(sec:Secret)
RETURN sec.name AS name, sec.source AS source, sec.category AS category`

	// QueryForbiddenPatterns returns forbidden secret patterns for a tool.
	// Params: $ref (tool reference string)
	QueryForbiddenPatterns = `MATCH (t:Tool {reference: $ref})-[:HAS_PROFILE]->(p:Profile)
-[:FORBIDS]->(sp:SecretPattern)
RETURN sp.regex AS regex, sp.reason AS reason, p.risk_tier AS risk_tier`

	// QuerySecretViolations finds secrets a step has access to that are forbidden
	// by the tool's profile. This is the core scoper query.
	// Params: $step (step name)
	QuerySecretViolations = `MATCH (s:Step {name: $step})-[:USES]->(t:Tool)-[:HAS_PROFILE]->(p:Profile)
-[:FORBIDS]->(pat:SecretPattern)
MATCH (s)-[:HAS_ACCESS]->(sec:Secret)
WHERE sec.name =~ pat.regex
RETURN sec.name AS secret, pat.regex AS pattern, pat.reason AS reason,
       t.reference AS tool, p.risk_tier AS risk_tier`

	// QueryPipelineSteps returns all steps in a pipeline with their tools.
	// Params: $path (pipeline file path)
	QueryPipelineSteps = `MATCH (p:Pipeline {path: $path})-[:CONTAINS_STEP]->(s:Step)
OPTIONAL MATCH (s)-[:USES]->(t:Tool)
RETURN s.name AS step, s.job AS job, t.reference AS tool, t.ecosystem AS ecosystem
ORDER BY s.name`

	// QueryToolProfile returns the security profile for a tool.
	// Params: $ref (tool reference string)
	QueryToolProfile = `MATCH (t:Tool {reference: $ref})-[:HAS_PROFILE]->(p:Profile)
OPTIONAL MATCH (p)-[:REQUIRES]->(req:Secret)
OPTIONAL MATCH (p)-[:FORBIDS]->(pat:SecretPattern)
RETURN p.risk_tier AS risk_tier, p.version AS version,
       req.name AS required_secret, pat.regex AS forbidden_pattern, pat.reason AS reason`
)
