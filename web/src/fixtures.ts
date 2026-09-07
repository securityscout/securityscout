export const engagement = {
  id: "eng_1",
  name: "acme-web",
  org: "acme",
} as const;

export const run = {
  id: "run_1",
  engagement_id: "eng_1",
  mode: "triage",
  status: "queued",
} as const;

export const findings = [
  {
    id: "f1",
    repo_url: "https://github.com/acme/app.git",
    sha: "deadbeefcafebabedeadbeefcafebabe",
    rule_id: "rule.x",
    file: "src/a.py",
    line: 1,
    status: "needs_review",
    run_id: "run_1",
    source_kind: "sast_csv",
    severity: "High",
    vuln_class: "CWE-89",
    proof: {
      kind: "harness",
      artifact_uri: "poc/f1.py",
      replay: { command: "pytest poc/f1.py", exit_code: 0 },
    },
  },
  {
    id: "f2",
    repo_url: "https://github.com/acme/app.git",
    sha: "deadbeefcafebabedeadbeefcafebabe",
    rule_id: "rule.y",
    file: "src/b.py",
    line: 2,
    status: "done",
    run_id: "run_1",
    source_kind: "sast_csv",
    severity: "Medium",
    vuln_class: "CWE-79",
    proof: {
      kind: "harness",
      artifact_uri: "poc/f2.py",
      replay: { command: "pytest poc/f2.py", exit_code: 0 },
    },
  },
] as const;

export type Finding = (typeof findings)[number];

export function findingsForEngagement(engId: string): Finding[] {
  if (run.engagement_id !== engId) {
    return [];
  }
  return findings.filter((row) => row.run_id === run.id);
}

export function findingById(findingId: string): Finding | undefined {
  return findings.find((row) => row.id === findingId);
}
