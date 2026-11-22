// A client for the Sophos Fusion Cases GraphQL API that installs a library case rule, for
// tools/case-rule-install.mjs. It sends only the documents below: reads of case rules and
// templates, the YAML import, createCaseRule and updateCaseRule. Never a delete, and nothing that
// touches a case. Credentials and the token never reach the output.
//
// What a lab tenant showed (20/11 to 22/11/2026): importInvestigationResources takes the YAML that
// Automatic Cases exports, creates the template and the rule and links them by name, keeps the file's
// state, and puts the rule after the tenant's own rules whatever order the file has. An imported
// rule opened no case until it was saved once more with updateCaseRule and no change; a rule made
// with createCaseRule worked at once. createCaseRule inserts at the order it is given and moves the
// tenant's rules from there down one, so the install gives it the order after the last rule.

import { SearchClient, GRAPHQL_URL } from './fusion-search.mjs';

const RULE = 'id name title description tags type order state filter appendFilter appendComment groupBy groupCount groupDuration groupExtendOnAppend searchQueries searchWindow tenantFilter skipDetectionPrioritization isGlobal updatedAt template { id name }';

export const CASE_DOCUMENTS = {
  caseRules: `query CaseRuleInstallRules($a: CaseRulesArguments!) {
  caseRules(arguments: $a) { totalCount rules { id name title order state updatedAt template { id name } } }
}`,
  caseRule: `query CaseRuleInstallRule($a: CaseRuleArguments!) {
  caseRule(arguments: $a) { ${RULE} }
}`,
  caseTemplate: `query CaseRuleInstallTemplate($a: CaseTemplateArguments!) {
  caseTemplate(arguments: $a) { id name title }
}`,
  createCaseRule: `mutation CaseRuleInstallCreate($i: CreateCaseRuleInput!) {
  createCaseRule(input: $i) { ${RULE} }
}`,
  updateCaseRule: `mutation CaseRuleInstallUpdate($i: UpdateCaseRuleInput!) {
  updateCaseRule(input: $i) { ${RULE} }
}`,
};

export const IMPORT_DOCUMENT = 'mutation CaseRuleInstallImport($input: ImportInvestigationResourcesInput!) { importInvestigationResources(input: $input) { __typename ... on InvestigationRule { id name title order state template { id name } } ... on InvestigationTemplate { id name title } } }';

// The fields updateCaseRule takes back unchanged. The order is left out: a rule keeps its place
// when the update doesn't name one.
export const UPDATE_KEYS = ['title', 'description', 'tags', 'state', 'filter', 'appendFilter', 'appendComment', 'groupBy', 'groupCount', 'groupDuration', 'groupExtendOnAppend', 'searchQueries', 'searchWindow', 'tenantFilter', 'skipDetectionPrioritization', 'isGlobal'];

export function casesClient(creds, opts = {}) {
  return new SearchClient(creds, { ...opts, documents: CASE_DOCUMENTS, retry: ['caseRules', 'caseRule', 'caseTemplate'] });
}

// Sends a YAML file to importInvestigationResources, as the GraphQL multipart upload it takes.
// Returns the resources it created or updated: [{__typename, id, name, ...}].
export async function importYaml(client, yamlText, { fileName = 'case-rule.yaml' } = {}) {
  const tenant = await client.resolveTenant();
  const token = await client.getToken();
  const form = new FormData();
  form.append('operations', JSON.stringify({ query: IMPORT_DOCUMENT, variables: { input: { file: null } } }));
  form.append('map', JSON.stringify({ 0: ['variables.input.file'] }));
  form.append('0', new Blob([yamlText], { type: 'application/x-yaml' }), fileName);
  const res = await client.fetch(GRAPHQL_URL, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'X-Tenant-ID': tenant, Accept: 'application/json', 'Apollo-Require-Preflight': 'true' },
    body: form,
    redirect: 'manual',
  });
  if (res.status >= 300 && res.status < 400) throw new Error(`${new URL(GRAPHQL_URL).host} answered with a redirect (HTTP ${res.status}), which this tool refuses to follow`);
  const text = await res.text();
  let body = null;
  try { body = JSON.parse(text); } catch { body = null; }
  const errors = body && Array.isArray(body.errors) ? body.errors.map((e) => e.message).join('; ') : '';
  if (!res.ok || !body || errors || !body.data || !body.data.importInvestigationResources) throw new Error(`importInvestigationResources failed (HTTP ${res.status}): ${errors || text.slice(0, 300)}`);
  return body.data.importInvestigationResources;
}

export async function allCaseRules(client) {
  const out = [];
  for (let page = 1; page < 50; page++) {
    const d = await client.request('caseRules', { a: { page, perPage: 100 } });
    out.push(...(d.rules || []));
    if (out.length >= d.totalCount || !(d.rules || []).length) break;
  }
  return out;
}

// Reads until the read returns something that passes ok, since reads can lag a write.
export async function readUntil(read, ok, { tries = 10, waitMs = 2000 } = {}) {
  let v = null;
  for (let i = 0; i < tries; i++) {
    try { v = await read(); } catch { v = null; }
    if (ok(v)) return v;
    await new Promise((r) => setTimeout(r, waitMs));
  }
  return v;
}

// The createCaseRule input for the rule document of a case-rule.yaml, at the given order.
export function createInput(rule, templateId, order) {
  const out = {
    name: rule.name, title: rule.title, tags: rule.tags || [], type: rule.type || 'STATIC', order, state: rule.state,
    filter: rule.filter, appendFilter: rule.append_filter || '', groupBy: rule.group_by, groupCount: rule.group_count,
    skipDetectionPrioritization: rule.skip_alert_prioritization === true, isGlobal: rule.is_global === true, templateId,
  };
  if (rule.description) out.description = rule.description;
  return out;
}

// The updateCaseRule input that saves a rule again with every value it holds.
export function resaveInput(current) {
  const out = { id: current.id };
  for (const k of UPDATE_KEYS) if (current[k] !== null && current[k] !== undefined) out[k] = current[k];
  out.templateId = current.template && current.template.id;
  return out;
}
