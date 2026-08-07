import { describe, expect, it } from 'vitest';
import { listingGrants, parseAuthCanIList, permissionsNeedingProbe } from './rbac-listing.js';

/** Real output from an admin account, whose single wildcard rule covers everything. */
const ADMIN = [
  'Resources                                       Non-Resource URLs   Resource Names   Verbs',
  '*.*                                             []                  []               [*]',
  '                                                [*]                 []               [*]',
  'selfsubjectreviews.authentication.k8s.io        []                  []               [create]',
  '                                                [/healthz]          []               [get]',
].join('\n');

/** The shape a namespace-scoped role produces: named resources, explicit verb lists. */
const SCOPED = [
  'Resources                                    Non-Resource URLs   Resource Names   Verbs',
  'pods                                         []                  []               [create get delete watch]',
  'pods/exec                                    []                  []               [create]',
  'secrets                                      []                  []               [create get delete update]',
  'deployments.apps                             []                  []               [create get delete list]',
  'services                                     []                  []               [create get delete]',
].join('\n');

const REQUIRED = [
  ['create', 'pods'],
  ['delete', 'pods'],
  ['watch', 'pods'],
  ['create', 'pods/exec'],
  ['update', 'secrets'],
  ['list', 'deployments.apps'],
];

describe('permissions read from a single listing', () => {
  it('reads a wildcard rule as covering every permission asked about', () => {
    const rules = parseAuthCanIList(ADMIN);
    expect(permissionsNeedingProbe(rules, REQUIRED)).toEqual([]);
  });

  it('reads named resources and their verbs', () => {
    const rules = parseAuthCanIList(SCOPED);
    expect(listingGrants(rules, 'create', 'pods')).toBe(true);
    expect(listingGrants(rules, 'watch', 'pods')).toBe(true);
    expect(listingGrants(rules, 'create', 'pods/exec')).toBe(true);
    expect(listingGrants(rules, 'update', 'secrets')).toBe(true);
    expect(listingGrants(rules, 'list', 'deployments.apps')).toBe(true);
  });

  it('leaves anything the listing does not cover to be asked about directly', () => {
    const rules = parseAuthCanIList(SCOPED);
    // Absent from the listing entirely, and a verb the listed rule does not carry.
    expect(permissionsNeedingProbe(rules, [
      ['create', 'networkpolicies.networking.k8s.io'],
      ['list', 'pods'],
    ])).toEqual([
      ['create', 'networkpolicies.networking.k8s.io'],
      ['list', 'pods'],
    ]);
  });

  it('ignores rules about URL paths rather than API resources', () => {
    // `[/healthz] [] [get]` grants `get` on a path; reading it as a resource rule would
    // hand out `get` on whatever happened to be asked about.
    const rules = parseAuthCanIList(ADMIN.split('\n').filter((line) => !line.startsWith('*.*')).join('\n'));
    expect(listingGrants(rules, 'get', 'pods')).toBe(false);
  });

  it('does not treat a rule limited to named objects as a rule about the resource', () => {
    const listing = [
      'Resources   Non-Resource URLs   Resource Names   Verbs',
      'secrets     []                  [one-secret]     [get]',
    ].join('\n');
    expect(listingGrants(parseAuthCanIList(listing), 'get', 'secrets')).toBe(false);
  });

  it('treats an unreadable listing as settling nothing', () => {
    // A failed call passes an empty listing, and an unfamiliar table must behave the same
    // way: everything falls through to the probe rather than being assumed granted.
    expect(permissionsNeedingProbe([], REQUIRED)).toEqual(REQUIRED);
    expect(permissionsNeedingProbe(parseAuthCanIList('error: you must be logged in'), REQUIRED)).toEqual(REQUIRED);
    expect(parseAuthCanIList(undefined)).toEqual([]);
  });
});
