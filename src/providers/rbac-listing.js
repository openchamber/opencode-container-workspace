/**
 * Reading permissions from one `kubectl auth can-i --list` instead of one process per
 * permission.
 *
 * There are twenty-six permissions to establish, and asking about each one separately
 * costs about 3.6 seconds on Windows — process creation, not the cluster, and raising the
 * concurrency does not help because the spawns are what saturates. The same answer as a
 * single listing costs about 250 milliseconds. That difference is the readiness check
 * feeling instant rather than looking stuck.
 *
 * The listing is a table meant for people, so parsing it is the fragile part. It is used
 * only to *grant*: a permission the rules clearly cover is settled, and anything else —
 * an unfamiliar row, a wildcard shape not handled here, a listing that failed outright —
 * falls through to the explicit probe that was always there. A parse that understands
 * less is slower, never wrong.
 */

/** One rule from the listing: which resources it names and which verbs it allows. */
export function parseAuthCanIList(output) {
  const rules = [];
  for (const line of String(output ?? '').split(/\r?\n/)) {
    // Three bracketed columns follow the resource: non-resource URLs, resource names,
    // verbs. Anchoring on them avoids depending on the column widths, which shift with
    // the longest resource name in the table.
    const match = /^(\S*)\s+\[([^\]]*)\]\s+\[([^\]]*)\]\s+\[([^\]]*)\]\s*$/.exec(line);
    if (!match) continue;
    const [, resourceColumn, , resourceNames, verbColumn] = match;
    // A rule limited to named objects does not grant the verb on the resource in general,
    // and a row with no resource is about a URL path rather than an API resource.
    if (!resourceColumn || resourceNames.trim()) continue;
    const verbs = verbColumn.split(/\s+/).filter(Boolean);
    if (verbs.length === 0) continue;
    rules.push({ resources: resourceColumn.split(',').filter(Boolean), verbs });
  }
  return rules;
}

function ruleGrants(rule, verb, resource) {
  if (!rule.verbs.includes('*') && !rule.verbs.includes(verb)) return false;
  return rule.resources.some((candidate) => candidate === '*.*' || candidate === '*' || candidate === resource);
}

/** Whether the listing settles this permission. Unsure is reported as not granted. */
export function listingGrants(rules, verb, resource) {
  return rules.some((rule) => ruleGrants(rule, verb, resource));
}

/** The permissions the listing could not settle, which still need asking about directly. */
export function permissionsNeedingProbe(rules, required) {
  return required.filter(([verb, resource]) => !listingGrants(rules, verb, resource));
}
