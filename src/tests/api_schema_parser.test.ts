/**
 * Tests for API Schema Parser
 *
 * Covers OpenAPI 3.x, Swagger 2.x, and GraphQL introspection parsing.
 */

import { describe, it, expect } from 'vitest';
import {
  parseAPISpec,
  schemaToEndpoints,
  generateSchemaBasedTasks,
  API_SPEC_PATHS,
  GRAPHQL_INTROSPECTION_QUERY,
} from '../core/discovery/api_schema_parser';

// ─── OpenAPI 3.x Fixtures ──────────────────────────────────────────────────

const OPENAPI3_SPEC = {
  openapi: '3.0.3',
  info: { title: 'Juice Shop API', version: '1.0.0' },
  servers: [{ url: 'http://localhost:3001' }],
  paths: {
    '/api/Users': {
      get: {
        operationId: 'listUsers',
        summary: 'List all users',
        parameters: [
          { name: 'q', in: 'query', required: false, schema: { type: 'string' } },
          { name: 'limit', in: 'query', required: false, schema: { type: 'integer' } },
        ],
        responses: { '200': { description: 'OK' } },
      },
      post: {
        operationId: 'createUser',
        summary: 'Create a user',
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  email: { type: 'string' },
                  password: { type: 'string' },
                  role: { type: 'string' },
                },
                required: ['email', 'password'],
              },
            },
          },
        },
        responses: { '201': { description: 'Created' } },
      },
    },
    '/api/Users/{id}': {
      get: {
        operationId: 'getUser',
        summary: 'Get user by ID',
        parameters: [
          { name: 'id', in: 'path', required: true, schema: { type: 'integer' } },
        ],
        responses: { '200': { description: 'OK' } },
        security: [{ bearerAuth: [] }],
      },
      delete: {
        operationId: 'deleteUser',
        parameters: [
          { name: 'id', in: 'path', required: true, schema: { type: 'integer' } },
        ],
        responses: { '204': { description: 'Deleted' } },
      },
    },
    '/api/Products/{id}/reviews': {
      post: {
        operationId: 'addReview',
        parameters: [
          { name: 'id', in: 'path', required: true, schema: { type: 'integer' } },
        ],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  message: { type: 'string' },
                  author: { type: 'string' },
                },
              },
            },
          },
        },
        responses: { '201': { description: 'Created' } },
      },
    },
    '/api/Feedbacks': {
      post: {
        operationId: 'submitFeedback',
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  comment: { type: 'string' },
                  rating: { type: 'integer' },
                },
              },
            },
          },
        },
        responses: { '201': { description: 'Created' } },
      },
    },
    '/redirect': {
      get: {
        operationId: 'redirect',
        parameters: [
          { name: 'to', in: 'query', required: true, schema: { type: 'string' } },
        ],
        responses: { '302': { description: 'Redirect' } },
      },
    },
    '/profile/image/upload': {
      post: {
        operationId: 'uploadImage',
        requestBody: {
          required: true,
          content: {
            'multipart/form-data': {
              schema: {
                type: 'object',
                properties: {
                  file: { type: 'string', format: 'binary' },
                },
              },
            },
          },
        },
        responses: { '200': { description: 'OK' } },
      },
    },
    '/rest/user/login': {
      post: {
        operationId: 'login',
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  email: { type: 'string' },
                  password: { type: 'string' },
                },
              },
            },
          },
        },
        responses: { '200': { description: 'OK' } },
      },
    },
    '/api/Complaints': {
      post: {
        operationId: 'fileComplaint',
        requestBody: {
          required: true,
          content: {
            'multipart/form-data': {
              schema: {
                type: 'object',
                properties: {
                  message: { type: 'string' },
                  file: { type: 'string', format: 'binary' },
                },
              },
            },
          },
        },
        responses: { '201': { description: 'Created' } },
      },
    },
  },
};

// ─── Swagger 2.x Fixtures ──────────────────────────────────────────────────

const SWAGGER2_SPEC = {
  swagger: '2.0',
  info: { title: 'Legacy API', version: '1.0' },
  host: 'api.example.com',
  basePath: '/v1',
  schemes: ['https'],
  paths: {
    '/users': {
      get: {
        operationId: 'getUsers',
        parameters: [
          { name: 'page', in: 'query', type: 'integer' },
          { name: 'search', in: 'query', type: 'string' },
        ],
        responses: { '200': { description: 'OK' } },
      },
      post: {
        operationId: 'createUser',
        parameters: [
          {
            name: 'body',
            in: 'body',
            required: true,
            schema: {
              type: 'object',
              properties: {
                name: { type: 'string' },
                email: { type: 'string' },
              },
            },
          },
        ],
        responses: { '201': { description: 'Created' } },
      },
    },
    '/users/{user_id}': {
      get: {
        operationId: 'getUser',
        parameters: [
          { name: 'user_id', in: 'path', type: 'integer', required: true },
        ],
        responses: { '200': { description: 'OK' } },
      },
    },
  },
};

// ─── GraphQL Fixtures ───────────────────────────────────────────────────────

const GRAPHQL_INTROSPECTION = {
  data: {
    __schema: {
      queryType: { name: 'Query' },
      mutationType: { name: 'Mutation' },
      types: [
        {
          name: 'Query',
          kind: 'OBJECT',
          fields: [
            {
              name: 'user',
              args: [
                { name: 'id', type: { name: 'ID', kind: 'SCALAR', ofType: null } },
              ],
              type: { name: 'User', kind: 'OBJECT', ofType: null },
            },
            {
              name: 'users',
              args: [
                { name: 'search', type: { name: 'String', kind: 'SCALAR', ofType: null } },
                { name: 'limit', type: { name: 'Int', kind: 'SCALAR', ofType: null } },
              ],
              type: { name: null, kind: 'LIST', ofType: { name: 'User', kind: 'OBJECT' } },
            },
          ],
        },
        {
          name: 'Mutation',
          kind: 'OBJECT',
          fields: [
            {
              name: 'createUser',
              args: [
                { name: 'name', type: { name: 'String', kind: 'SCALAR', ofType: null } },
                { name: 'email', type: { name: 'String', kind: 'SCALAR', ofType: null } },
              ],
              type: { name: 'User', kind: 'OBJECT', ofType: null },
            },
            {
              name: 'deleteUser',
              args: [
                { name: 'id', type: { name: null, kind: 'NON_NULL', ofType: { name: 'ID', kind: 'SCALAR' } } },
              ],
              type: { name: 'Boolean', kind: 'SCALAR', ofType: null },
            },
          ],
        },
        {
          name: '__Schema',
          kind: 'OBJECT',
          fields: [{ name: 'types', args: [], type: { name: null, kind: 'LIST', ofType: { name: '__Type', kind: 'OBJECT' } } }],
        },
        {
          name: 'User',
          kind: 'OBJECT',
          fields: [
            { name: 'id', args: [], type: { name: 'ID', kind: 'SCALAR', ofType: null } },
            { name: 'name', args: [], type: { name: 'String', kind: 'SCALAR', ofType: null } },
          ],
        },
      ],
    },
  },
};

// ─── Tests ──────────────────────────────────────────────────────────────────

describe('API Schema Parser', () => {
  describe('OpenAPI 3.x parsing', () => {
    it('detects OpenAPI 3.x format', () => {
      const schema = parseAPISpec(OPENAPI3_SPEC, 'http://localhost:3001');
      expect(schema.source).toBe('openapi');
      expect(schema.version).toBe('3.0.3');
      expect(schema.title).toBe('Juice Shop API');
    });

    it('resolves base URL from servers array', () => {
      const schema = parseAPISpec(OPENAPI3_SPEC, 'http://fallback.com');
      expect(schema.baseUrl).toBe('http://localhost:3001');
    });

    it('extracts all endpoints', () => {
      const schema = parseAPISpec(OPENAPI3_SPEC, 'http://localhost:3001');
      expect(schema.endpoints.length).toBe(10);
    });

    it('parses path parameters', () => {
      const schema = parseAPISpec(OPENAPI3_SPEC, 'http://localhost:3001');
      const getUser = schema.endpoints.find(e => e.operationId === 'getUser');
      expect(getUser).toBeDefined();
      expect(getUser!.parameters).toHaveLength(1);
      expect(getUser!.parameters[0].name).toBe('id');
      expect(getUser!.parameters[0].location).toBe('path');
      expect(getUser!.parameters[0].required).toBe(true);
    });

    it('parses query parameters', () => {
      const schema = parseAPISpec(OPENAPI3_SPEC, 'http://localhost:3001');
      const listUsers = schema.endpoints.find(e => e.operationId === 'listUsers');
      expect(listUsers).toBeDefined();
      expect(listUsers!.parameters).toHaveLength(2);
      expect(listUsers!.parameters[0].name).toBe('q');
      expect(listUsers!.parameters[0].location).toBe('query');
    });

    it('parses JSON request body', () => {
      const schema = parseAPISpec(OPENAPI3_SPEC, 'http://localhost:3001');
      const createUser = schema.endpoints.find(e => e.operationId === 'createUser');
      expect(createUser).toBeDefined();
      expect(createUser!.requestBody).toBeDefined();
      expect(createUser!.requestBody!.contentType).toBe('application/json');
      expect(createUser!.requestBody!.fields).toHaveLength(3);
      expect(createUser!.requestBody!.fields.find(f => f.name === 'email')!.required).toBe(true);
    });

    it('parses multipart request body', () => {
      const schema = parseAPISpec(OPENAPI3_SPEC, 'http://localhost:3001');
      const upload = schema.endpoints.find(e => e.operationId === 'uploadImage');
      expect(upload).toBeDefined();
      expect(upload!.requestBody!.contentType).toBe('multipart/form-data');
    });

    it('extracts security requirements', () => {
      const schema = parseAPISpec(OPENAPI3_SPEC, 'http://localhost:3001');
      const getUser = schema.endpoints.find(e => e.operationId === 'getUser');
      expect(getUser!.security).toEqual(['bearerAuth']);
    });
  });

  describe('Swagger 2.x parsing', () => {
    it('detects Swagger 2.x format', () => {
      const schema = parseAPISpec(SWAGGER2_SPEC, 'https://api.example.com');
      expect(schema.source).toBe('swagger');
      expect(schema.version).toBe('2.0');
    });

    it('resolves base URL from host + basePath + schemes', () => {
      const schema = parseAPISpec(SWAGGER2_SPEC, 'https://api.example.com');
      expect(schema.baseUrl).toBe('https://api.example.com/v1');
    });

    it('extracts endpoints from Swagger paths', () => {
      const schema = parseAPISpec(SWAGGER2_SPEC, 'https://api.example.com');
      expect(schema.endpoints.length).toBe(3);
    });

    it('converts body parameters to requestBody', () => {
      const schema = parseAPISpec(SWAGGER2_SPEC, 'https://api.example.com');
      const createUser = schema.endpoints.find(e => e.operationId === 'createUser');
      expect(createUser!.requestBody).toBeDefined();
      expect(createUser!.requestBody!.fields).toHaveLength(2);
    });

    it('parses path parameters from Swagger', () => {
      const schema = parseAPISpec(SWAGGER2_SPEC, 'https://api.example.com');
      const getUser = schema.endpoints.find(e => e.operationId === 'getUser');
      expect(getUser!.parameters[0].name).toBe('user_id');
      expect(getUser!.parameters[0].location).toBe('path');
    });
  });

  describe('GraphQL introspection parsing', () => {
    it('detects GraphQL introspection format', () => {
      const schema = parseAPISpec(GRAPHQL_INTROSPECTION, 'http://localhost:3001');
      expect(schema.source).toBe('graphql');
    });

    it('extracts Query operations', () => {
      const schema = parseAPISpec(GRAPHQL_INTROSPECTION, 'http://localhost:3001');
      const queries = schema.endpoints.filter(e => e.tags?.includes('Query'));
      expect(queries).toHaveLength(2);
      expect(queries[0].operationId).toBe('Query.user');
    });

    it('extracts Mutation operations', () => {
      const schema = parseAPISpec(GRAPHQL_INTROSPECTION, 'http://localhost:3001');
      const mutations = schema.endpoints.filter(e => e.tags?.includes('Mutation'));
      expect(mutations).toHaveLength(2);
    });

    it('skips internal __ types', () => {
      const schema = parseAPISpec(GRAPHQL_INTROSPECTION, 'http://localhost:3001');
      expect(schema.endpoints.every(e => !e.operationId?.startsWith('__'))).toBe(true);
    });

    it('skips non-root types like User', () => {
      const schema = parseAPISpec(GRAPHQL_INTROSPECTION, 'http://localhost:3001');
      // User type fields should NOT appear as endpoints
      expect(schema.endpoints.find(e => e.operationId === 'User.id')).toBeUndefined();
    });

    it('resolves NON_NULL types', () => {
      const schema = parseAPISpec(GRAPHQL_INTROSPECTION, 'http://localhost:3001');
      const deleteUser = schema.endpoints.find(e => e.operationId === 'Mutation.deleteUser');
      expect(deleteUser!.parameters[0].type).toContain('!');
    });
  });

  describe('schemaToEndpoints', () => {
    it('converts API schema to DiscoveredEndpoint format', () => {
      const schema = parseAPISpec(OPENAPI3_SPEC, 'http://localhost:3001');
      const endpoints = schemaToEndpoints(schema);

      expect(endpoints.length).toBe(schema.endpoints.length);
      expect(endpoints[0].source).toBe('openapi');
      expect(endpoints[0].url).toContain('http://localhost:3001');
    });

    it('merges params and body fields into parameters', () => {
      const schema = parseAPISpec(OPENAPI3_SPEC, 'http://localhost:3001');
      const endpoints = schemaToEndpoints(schema);
      const createUser = endpoints.find(e => e.url.includes('/api/Users') && e.method === 'POST');
      expect(createUser!.parameters).toContain('email');
      expect(createUser!.parameters).toContain('password');
    });
  });

  describe('generateSchemaBasedTasks', () => {
    it('generates IDOR tasks for ID parameters', () => {
      const schema = parseAPISpec(OPENAPI3_SPEC, 'http://localhost:3001');
      const tasks = generateSchemaBasedTasks(schema);
      const idorTasks = tasks.filter(t => t.agentType === 'idor_hunter');
      expect(idorTasks.length).toBeGreaterThan(0);
    });

    it('generates SQLi tasks for data endpoints', () => {
      const schema = parseAPISpec(OPENAPI3_SPEC, 'http://localhost:3001');
      const tasks = generateSchemaBasedTasks(schema);
      const sqliTasks = tasks.filter(t => t.agentType === 'sqli_hunter');
      expect(sqliTasks.length).toBeGreaterThan(0);
    });

    it('generates XSS tasks for reflectable parameters', () => {
      const schema = parseAPISpec(OPENAPI3_SPEC, 'http://localhost:3001');
      const tasks = generateSchemaBasedTasks(schema);
      const xssTasks = tasks.filter(t => t.agentType === 'xss_hunter');
      // 'q' (search), 'message', 'comment' should trigger XSS tasks
      expect(xssTasks.length).toBeGreaterThan(0);
    });

    it('generates file upload tasks for multipart endpoints', () => {
      const schema = parseAPISpec(OPENAPI3_SPEC, 'http://localhost:3001');
      const tasks = generateSchemaBasedTasks(schema);
      const uploadTasks = tasks.filter(t => t.agentType === 'path_traversal_hunter');
      expect(uploadTasks.length).toBeGreaterThanOrEqual(1);
    });

    it('generates auth tasks for login endpoints', () => {
      const schema = parseAPISpec(OPENAPI3_SPEC, 'http://localhost:3001');
      const tasks = generateSchemaBasedTasks(schema);
      const authTasks = tasks.filter(t => t.agentType === 'oauth_hunter');
      expect(authTasks.length).toBeGreaterThanOrEqual(1);
    });

    it('generates GraphQL tasks from introspection', () => {
      const schema = parseAPISpec(GRAPHQL_INTROSPECTION, 'http://localhost:3001');
      const tasks = generateSchemaBasedTasks(schema);
      const gqlTasks = tasks.filter(t => t.agentType === 'graphql_hunter');
      expect(gqlTasks.length).toBe(4); // 2 queries + 2 mutations
    });
  });

  describe('format detection', () => {
    it('rejects unrecognized formats', () => {
      expect(() => parseAPISpec({ foo: 'bar' }, 'http://test.com')).toThrow(
        'Unrecognized API spec format',
      );
    });
  });

  describe('constants', () => {
    it('provides common API spec paths', () => {
      expect(API_SPEC_PATHS).toContain('/swagger.json');
      expect(API_SPEC_PATHS).toContain('/openapi.json');
      expect(API_SPEC_PATHS).toContain('/api-docs');
    });

    it('provides GraphQL introspection query', () => {
      expect(GRAPHQL_INTROSPECTION_QUERY).toContain('__schema');
      expect(GRAPHQL_INTROSPECTION_QUERY).toContain('types');
      expect(GRAPHQL_INTROSPECTION_QUERY).toContain('fields');
    });
  });
});
