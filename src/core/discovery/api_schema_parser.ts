/**
 * API Schema Parser — OpenAPI/Swagger/GraphQL → DiscoveredEndpoint[]
 *
 * Parses API specifications into the same DiscoveredEndpoint format used by
 * the crawler and attack surface mapper. This enables the orchestrator to
 * generate targeted vulnerability tasks for every documented endpoint.
 *
 * Supports:
 * - OpenAPI 3.x (JSON/YAML → JSON)
 * - Swagger 2.x (JSON)
 * - GraphQL introspection results
 *
 * Discovery from common paths:
 * - /api-docs, /swagger.json, /openapi.json, /v2/api-docs
 * - GraphQL: { __schema { types { ... } } }
 */

import type { DiscoveredEndpoint } from './crawler';

// ─── Types ──────────────────────────────────────────────────────────────────

export type SchemaSource = 'openapi' | 'swagger' | 'graphql';

export interface APISchema {
  source: SchemaSource;
  version: string;
  title: string;
  baseUrl: string;
  endpoints: ParsedEndpoint[];
  rawSpec: Record<string, unknown>;
  parsedAt: number;
}

export interface ParsedEndpoint {
  path: string;
  method: string;
  operationId?: string;
  summary?: string;
  parameters: ParsedParameter[];
  requestBody?: ParsedRequestBody;
  responses: Record<string, { description: string }>;
  security?: string[];
  tags?: string[];
}

export interface ParsedParameter {
  name: string;
  location: 'path' | 'query' | 'header' | 'cookie';
  required: boolean;
  type: string;
  description?: string;
}

export interface ParsedRequestBody {
  contentType: string;
  required: boolean;
  fields: Array<{ name: string; type: string; required: boolean }>;
}

// Common paths where API specs are typically served
export const API_SPEC_PATHS = [
  '/swagger.json',
  '/openapi.json',
  '/api-docs',
  '/v2/api-docs',
  '/v3/api-docs',
  '/swagger/v1/swagger.json',
  '/api/swagger.json',
  '/api/openapi.json',
  '/docs/api.json',
  '/_catalog',
] as const;

// GraphQL introspection query
export const GRAPHQL_INTROSPECTION_QUERY = `{
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields {
        name
        args {
          name
          type { name kind ofType { name kind } }
        }
        type { name kind ofType { name kind } }
      }
    }
  }
}`;

// ─── OpenAPI 3.x Parser ────────────────────────────────────────────────────

function parseOpenAPI3(spec: Record<string, unknown>, baseUrl: string): APISchema {
  const info = (spec.info as Record<string, unknown>) ?? {};
  const servers = (spec.servers as Array<Record<string, unknown>>) ?? [];
  const paths = (spec.paths as Record<string, Record<string, unknown>>) ?? {};

  // Resolve base URL from servers or fallback
  const resolvedBase = servers.length > 0
    ? String(servers[0].url ?? baseUrl)
    : baseUrl;

  const endpoints: ParsedEndpoint[] = [];

  for (const [path, methods] of Object.entries(paths)) {
    for (const [method, operation] of Object.entries(methods)) {
      if (['get', 'post', 'put', 'patch', 'delete', 'head', 'options'].includes(method)) {
        const op = operation as Record<string, unknown>;
        endpoints.push(parseOperation(path, method.toUpperCase(), op, spec));
      }
    }
  }

  return {
    source: 'openapi',
    version: String(spec.openapi ?? '3.0.0'),
    title: String(info.title ?? 'Unknown API'),
    baseUrl: resolvedBase,
    endpoints,
    rawSpec: spec,
    parsedAt: Date.now(),
  };
}

function parseOperation(
  path: string,
  method: string,
  op: Record<string, unknown>,
  spec: Record<string, unknown>,
): ParsedEndpoint {
  const params = (op.parameters as Array<Record<string, unknown>>) ?? [];
  const parsedParams: ParsedParameter[] = params.map(p => ({
    name: String(p.name ?? ''),
    location: String(p.in ?? 'query') as ParsedParameter['location'],
    required: Boolean(p.required),
    type: resolveParamType(p.schema as Record<string, unknown> | undefined),
    description: p.description ? String(p.description) : undefined,
  }));

  let requestBody: ParsedRequestBody | undefined;
  if (op.requestBody) {
    requestBody = parseRequestBody(op.requestBody as Record<string, unknown>, spec);
  }

  const responses: Record<string, { description: string }> = {};
  if (op.responses) {
    for (const [code, resp] of Object.entries(op.responses as Record<string, unknown>)) {
      const r = resp as Record<string, unknown>;
      responses[code] = { description: String(r.description ?? '') };
    }
  }

  // Extract security requirements
  const security: string[] = [];
  const securityReqs = (op.security as Array<Record<string, unknown>>) ?? [];
  for (const req of securityReqs) {
    security.push(...Object.keys(req));
  }

  return {
    path,
    method,
    operationId: op.operationId ? String(op.operationId) : undefined,
    summary: op.summary ? String(op.summary) : undefined,
    parameters: parsedParams,
    requestBody,
    responses,
    security: security.length > 0 ? security : undefined,
    tags: (op.tags as string[]) ?? undefined,
  };
}

function parseRequestBody(
  body: Record<string, unknown>,
  spec: Record<string, unknown>,
): ParsedRequestBody | undefined {
  const content = body.content as Record<string, unknown> | undefined;
  if (!content) return undefined;

  // Prefer JSON, then form-urlencoded, then multipart
  const contentTypes = [
    'application/json',
    'application/x-www-form-urlencoded',
    'multipart/form-data',
  ];

  for (const ct of contentTypes) {
    const mediaType = content[ct] as Record<string, unknown> | undefined;
    if (mediaType) {
      const schema = resolveRef(mediaType.schema as Record<string, unknown>, spec);
      const fields = extractFieldsFromSchema(schema);
      return {
        contentType: ct,
        required: Boolean(body.required),
        fields,
      };
    }
  }

  // Fallback to first available content type
  const firstCt = Object.keys(content)[0];
  if (firstCt) {
    const mediaType = content[firstCt] as Record<string, unknown>;
    const schema = resolveRef(mediaType.schema as Record<string, unknown>, spec);
    return {
      contentType: firstCt,
      required: Boolean(body.required),
      fields: extractFieldsFromSchema(schema),
    };
  }

  return undefined;
}

// ─── Swagger 2.x Parser ────────────────────────────────────────────────────

function parseSwagger2(spec: Record<string, unknown>, baseUrl: string): APISchema {
  const info = (spec.info as Record<string, unknown>) ?? {};
  const host = String(spec.host ?? new URL(baseUrl).host);
  const basePath = String(spec.basePath ?? '/');
  const schemes = (spec.schemes as string[]) ?? ['https'];
  const paths = (spec.paths as Record<string, Record<string, unknown>>) ?? {};

  const resolvedBase = `${schemes[0]}://${host}${basePath}`;
  const endpoints: ParsedEndpoint[] = [];

  for (const [path, methods] of Object.entries(paths)) {
    for (const [method, operation] of Object.entries(methods)) {
      if (['get', 'post', 'put', 'patch', 'delete', 'head', 'options'].includes(method)) {
        const op = operation as Record<string, unknown>;
        const params = (op.parameters as Array<Record<string, unknown>>) ?? [];

        // Swagger 2.x has body params inline
        const parsedParams: ParsedParameter[] = [];
        let requestBody: ParsedRequestBody | undefined;

        for (const p of params) {
          if (String(p.in) === 'body') {
            const schema = resolveRef(p.schema as Record<string, unknown>, spec);
            requestBody = {
              contentType: 'application/json',
              required: Boolean(p.required),
              fields: extractFieldsFromSchema(schema),
            };
          } else if (String(p.in) === 'formData') {
            if (!requestBody) {
              requestBody = {
                contentType: 'application/x-www-form-urlencoded',
                required: false,
                fields: [],
              };
            }
            requestBody.fields.push({
              name: String(p.name),
              type: String(p.type ?? 'string'),
              required: Boolean(p.required),
            });
          } else {
            parsedParams.push({
              name: String(p.name ?? ''),
              location: String(p.in ?? 'query') as ParsedParameter['location'],
              required: Boolean(p.required),
              type: String(p.type ?? 'string'),
              description: p.description ? String(p.description) : undefined,
            });
          }
        }

        const responses: Record<string, { description: string }> = {};
        if (op.responses) {
          for (const [code, resp] of Object.entries(op.responses as Record<string, unknown>)) {
            const r = resp as Record<string, unknown>;
            responses[code] = { description: String(r.description ?? '') };
          }
        }

        endpoints.push({
          path,
          method: method.toUpperCase(),
          operationId: op.operationId ? String(op.operationId) : undefined,
          summary: op.summary ? String(op.summary) : undefined,
          parameters: parsedParams,
          requestBody,
          responses,
          tags: (op.tags as string[]) ?? undefined,
        });
      }
    }
  }

  return {
    source: 'swagger',
    version: String(spec.swagger ?? '2.0'),
    title: String(info.title ?? 'Unknown API'),
    baseUrl: resolvedBase,
    endpoints,
    rawSpec: spec,
    parsedAt: Date.now(),
  };
}

// ─── GraphQL Introspection Parser ──────────────────────────────────────────

export interface GraphQLField {
  name: string;
  args: Array<{ name: string; type: string }>;
  returnType: string;
  parentType: string;
}

function parseGraphQLIntrospection(
  result: Record<string, unknown>,
  baseUrl: string,
): APISchema {
  const schema = (result.data as Record<string, unknown>)?.__schema as Record<string, unknown>
    ?? (result.__schema as Record<string, unknown>)
    ?? result;

  const types = (schema.types as Array<Record<string, unknown>>) ?? [];
  const queryTypeName = (schema.queryType as Record<string, unknown>)?.name as string | undefined;
  const mutationTypeName = (schema.mutationType as Record<string, unknown>)?.name as string | undefined;

  const endpoints: ParsedEndpoint[] = [];

  for (const type of types) {
    const typeName = String(type.name ?? '');
    const kind = String(type.kind ?? '');

    // Skip internal types (prefixed with __)
    if (typeName.startsWith('__') || kind !== 'OBJECT') continue;

    // Only process Query and Mutation root types
    const isQuery = typeName === queryTypeName;
    const isMutation = typeName === mutationTypeName;
    if (!isQuery && !isMutation) continue;

    const fields = (type.fields as Array<Record<string, unknown>>) ?? [];
    for (const field of fields) {
      const fieldName = String(field.name ?? '');
      const args = (field.args as Array<Record<string, unknown>>) ?? [];

      const params: ParsedParameter[] = args.map(arg => ({
        name: String(arg.name ?? ''),
        location: 'query' as const,
        required: resolveGraphQLType(arg.type as Record<string, unknown>).includes('!'),
        type: resolveGraphQLType(arg.type as Record<string, unknown>),
      }));

      endpoints.push({
        path: `/graphql`,
        method: isMutation ? 'POST' : 'POST', // GraphQL always uses POST
        operationId: `${typeName}.${fieldName}`,
        summary: `GraphQL ${isQuery ? 'query' : 'mutation'}: ${fieldName}`,
        parameters: params,
        responses: { '200': { description: 'GraphQL response' } },
        tags: [isQuery ? 'Query' : 'Mutation'],
      });
    }
  }

  return {
    source: 'graphql',
    version: 'introspection',
    title: `GraphQL API (${endpoints.length} operations)`,
    baseUrl,
    endpoints,
    rawSpec: result,
    parsedAt: Date.now(),
  };
}

function resolveGraphQLType(typeObj: Record<string, unknown> | undefined): string {
  if (!typeObj) return 'unknown';
  const name = typeObj.name as string | null;
  const kind = String(typeObj.kind ?? '');
  const ofType = typeObj.ofType as Record<string, unknown> | undefined;

  if (kind === 'NON_NULL') return `${resolveGraphQLType(ofType)}!`;
  if (kind === 'LIST') return `[${resolveGraphQLType(ofType)}]`;
  return name ?? 'unknown';
}

// ─── Shared Utilities ───────────────────────────────────────────────────────

function resolveRef(
  schema: Record<string, unknown> | undefined,
  spec: Record<string, unknown>,
): Record<string, unknown> {
  if (!schema) return {};
  const ref = schema.$ref as string | undefined;
  if (!ref) return schema;

  // Resolve JSON Pointer (e.g., #/components/schemas/User → spec.components.schemas.User)
  const parts = ref.replace(/^#\//, '').split('/');
  let resolved: unknown = spec;
  for (const part of parts) {
    if (resolved && typeof resolved === 'object') {
      resolved = (resolved as Record<string, unknown>)[part];
    }
  }
  return (resolved as Record<string, unknown>) ?? {};
}

function resolveParamType(schema: Record<string, unknown> | undefined): string {
  if (!schema) return 'string';
  return String(schema.type ?? schema.format ?? 'string');
}

function extractFieldsFromSchema(
  schema: Record<string, unknown>,
): Array<{ name: string; type: string; required: boolean }> {
  const fields: Array<{ name: string; type: string; required: boolean }> = [];
  const properties = (schema.properties as Record<string, Record<string, unknown>>) ?? {};
  const required = (schema.required as string[]) ?? [];

  for (const [name, prop] of Object.entries(properties)) {
    fields.push({
      name,
      type: String(prop.type ?? 'string'),
      required: required.includes(name),
    });
  }

  return fields;
}

// ─── Public API ─────────────────────────────────────────────────────────────

/**
 * Auto-detect spec format and parse.
 */
export function parseAPISpec(
  spec: Record<string, unknown>,
  baseUrl: string,
): APISchema {
  if (spec.openapi && String(spec.openapi).startsWith('3')) {
    return parseOpenAPI3(spec, baseUrl);
  }
  if (spec.swagger && String(spec.swagger).startsWith('2')) {
    return parseSwagger2(spec, baseUrl);
  }
  if (spec.__schema || (spec.data as Record<string, unknown>)?.__schema) {
    return parseGraphQLIntrospection(spec, baseUrl);
  }
  throw new Error(
    'Unrecognized API spec format. Expected OpenAPI 3.x, Swagger 2.x, or GraphQL introspection.',
  );
}

/**
 * Convert parsed API schema into DiscoveredEndpoint[] for the attack surface mapper.
 */
export function schemaToEndpoints(schema: APISchema): DiscoveredEndpoint[] {
  return schema.endpoints.map(ep => {
    const fullUrl = schema.baseUrl.replace(/\/$/, '') + ep.path;
    const params: string[] = [
      ...ep.parameters.map(p => p.name),
      ...(ep.requestBody?.fields.map(f => f.name) ?? []),
    ];

    return {
      url: fullUrl,
      method: ep.method,
      source: 'openapi' as DiscoveredEndpoint['source'],
      parameters: params,
      contentType: ep.requestBody?.contentType,
    };
  });
}

/**
 * Generate vulnerability-targeted tasks from an API schema.
 * Maps each endpoint to the most relevant agent types based on
 * parameters, methods, and content types.
 */
export function generateSchemaBasedTasks(
  schema: APISchema,
): Array<{
  agentType: string;
  target: string;
  description: string;
  priority: number;
  parameters: Record<string, unknown>;
}> {
  const tasks: Array<{
    agentType: string;
    target: string;
    description: string;
    priority: number;
    parameters: Record<string, unknown>;
  }> = [];

  for (const ep of schema.endpoints) {
    const fullUrl = schema.baseUrl.replace(/\/$/, '') + ep.path;
    const paramNames = ep.parameters.map(p => p.name);
    const bodyFields = ep.requestBody?.fields.map(f => f.name) ?? [];
    const allParams = [...paramNames, ...bodyFields];

    // IDOR detection: ID-like parameters
    const idParams = allParams.filter(p =>
      /^(id|user_?id|uid|account_?id|org_?id|team_?id|project_?id|[a-z]+_?id)$/i.test(p),
    );
    if (idParams.length > 0) {
      tasks.push({
        agentType: 'idor_hunter',
        target: fullUrl,
        description: `Test IDOR on ${ep.method} ${ep.path} — ID params: ${idParams.join(', ')}`,
        priority: 9,
        parameters: { endpoint: fullUrl, method: ep.method, idParams },
      });
    }

    // SQL injection: any input parameter on data endpoints
    if (allParams.length > 0 && ['GET', 'POST', 'PUT', 'PATCH'].includes(ep.method)) {
      tasks.push({
        agentType: 'sqli_hunter',
        target: fullUrl,
        description: `Test SQLi on ${ep.method} ${ep.path} — params: ${allParams.join(', ')}`,
        priority: 8,
        parameters: { endpoint: fullUrl, method: ep.method, params: allParams },
      });
    }

    // XSS: parameters that might be reflected
    const reflectableParams = allParams.filter(p =>
      /^(q|query|search|name|title|message|comment|body|content|text|description|input|value|redirect|url|callback|next|return|ref)$/i.test(p),
    );
    if (reflectableParams.length > 0) {
      tasks.push({
        agentType: 'xss_hunter',
        target: fullUrl,
        description: `Test XSS on ${ep.method} ${ep.path} — reflectable: ${reflectableParams.join(', ')}`,
        priority: 7,
        parameters: { endpoint: fullUrl, method: ep.method, params: reflectableParams },
      });
    }

    // SSRF: URL-like parameters
    const urlParams = allParams.filter(p =>
      /^(url|uri|link|href|redirect|callback|webhook|proxy|fetch|load|src|source|dest|target|host|domain|site|endpoint|api_?url)$/i.test(p),
    );
    if (urlParams.length > 0) {
      tasks.push({
        agentType: 'ssrf_hunter',
        target: fullUrl,
        description: `Test SSRF on ${ep.method} ${ep.path} — URL params: ${urlParams.join(', ')}`,
        priority: 9,
        parameters: { endpoint: fullUrl, method: ep.method, urlParams },
      });
    }

    // File upload: multipart form endpoints
    if (ep.requestBody?.contentType === 'multipart/form-data') {
      tasks.push({
        agentType: 'path_traversal_hunter',
        target: fullUrl,
        description: `Test file upload on ${ep.method} ${ep.path}`,
        priority: 7,
        parameters: { endpoint: fullUrl, method: ep.method },
      });
    }

    // Auth-related endpoints
    if (/auth|login|signup|register|password|token|session|oauth/i.test(ep.path)) {
      tasks.push({
        agentType: 'oauth_hunter',
        target: fullUrl,
        description: `Test auth on ${ep.method} ${ep.path}`,
        priority: 8,
        parameters: { endpoint: fullUrl, method: ep.method },
      });
    }

    // GraphQL-specific attacks
    if (schema.source === 'graphql') {
      tasks.push({
        agentType: 'graphql_hunter',
        target: fullUrl,
        description: `Test GraphQL operation: ${ep.operationId ?? ep.summary ?? ep.path}`,
        priority: 8,
        parameters: { endpoint: fullUrl, operation: ep.operationId, args: paramNames },
      });
    }
  }

  return tasks;
}
