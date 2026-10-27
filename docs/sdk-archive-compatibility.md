# Project archive SDK compatibility

`echo.certforge.projects.archive` targets the existing tenant-scoped
`DELETE /v1/subscriber/projects/{project_id}` route. Its SDK contract is defined
in `scripts/generate_certforge_sdk_contract.py`, because the fleet adapter's
envelope and response handling extend the route's OpenAPI representation.

The request requires flat `command` and `project_id` fields. It may also include
an `options` object that mirrors those fields for fleet argument projections;
an options-only request remains invalid. The outer object rejects unknown
fields, while the compatibility options object remains open. Both project ID
locations require 1–128 ASCII characters, beginning with an alphanumeric
character and followed only by alphanumerics, `.`, `_`, `:`, or `-`.

The generator retains the intent of the deployed `fix-cap 25412 / 39521`
overlay. It additionally rejects trailing newlines: the old `$` regular
expression assertion allowed a final newline in some validators. The strict
end assertion now works with both ECMAScript and Python regular expressions.

A successful response may be `null` for HTTP 204 or an object from the SDK
adapter. Other response types are rejected. Registration preserves the
`command` and `project_id` projections, a minimum 20-second timeout, and the
existing `never_archive` flag. These settings do not change the capability's
scope, danger tier, tenant binding, credentials, route, or HTTP method.

Run `python scripts/generate_certforge_sdk_contract.py --write` after changing
the generator. The normal deployment transaction applies capability
registrations first, then the generated schema sync. The generator freshness
test and JSON Schema behavior tests prevent the generated files from silently
reverting this compatibility contract. Local test success does not establish
deployed service readiness or authorize a release.
