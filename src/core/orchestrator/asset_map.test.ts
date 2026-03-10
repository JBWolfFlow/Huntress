/**
 * AssetMap — Unit Tests
 *
 * Verifies the asset map builder correctly merges, deduplicates,
 * and queries discovered assets.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { AssetMapBuilder } from './asset_map';

describe('AssetMapBuilder', () => {
  let builder: AssetMapBuilder;

  beforeEach(() => {
    builder = new AssetMapBuilder('example.com');
  });

  describe('addSubdomain', () => {
    it('should add a new subdomain', () => {
      builder.addSubdomain({
        name: 'api.example.com',
        ips: ['1.2.3.4'],
        cnames: [],
        status: 'resolved',
        technologies: ['nginx'],
      });

      const map = builder.build();
      expect(map.subdomains).toHaveLength(1);
      expect(map.subdomains[0].name).toBe('api.example.com');
    });

    it('should merge duplicate subdomains', () => {
      builder.addSubdomain({
        name: 'api.example.com',
        ips: ['1.2.3.4'],
        cnames: [],
        status: 'unresolved',
        technologies: [],
      });
      builder.addSubdomain({
        name: 'api.example.com',
        ips: ['5.6.7.8'],
        cnames: ['lb.cloudflare.com'],
        status: 'resolved',
        technologies: ['nginx'],
      });

      const map = builder.build();
      expect(map.subdomains).toHaveLength(1);
      // Should merge IPs
      expect(map.subdomains[0].ips).toContain('1.2.3.4');
      expect(map.subdomains[0].ips).toContain('5.6.7.8');
      // Should upgrade status
      expect(map.subdomains[0].status).toBe('resolved');
    });
  });

  describe('addPort', () => {
    it('should add port information', () => {
      builder.addPort({
        host: 'example.com',
        port: 8080,
        service: 'http-alt',
        state: 'open',
      });

      const map = builder.build();
      expect(map.ports).toHaveLength(1);
      expect(map.ports[0].port).toBe(8080);
    });
  });

  describe('addEndpoint', () => {
    it('should add endpoint with parameters', () => {
      builder.addEndpoint({
        url: 'https://api.example.com/users?id=1&format=json',
        method: 'GET',
        params: [
          { name: 'id', type: 'query' },
          { name: 'format', type: 'query' },
        ],
        source: 'crawl',
      });

      const map = builder.build();
      expect(map.endpoints).toHaveLength(1);
      expect(map.endpoints[0].params).toHaveLength(2);
    });
  });

  describe('addTechnology', () => {
    it('should add and deduplicate technologies', () => {
      builder.addTechnology({ name: 'nginx', version: '1.21', category: 'server', confidence: 90 });
      builder.addTechnology({ name: 'nginx', version: '1.21', category: 'server', confidence: 95 });
      builder.addTechnology({ name: 'React', category: 'framework', confidence: 80 });

      const map = builder.build();
      expect(map.technologies).toHaveLength(2);
    });
  });

  describe('setWAF', () => {
    it('should set WAF info', () => {
      builder.setWAF({ name: 'Cloudflare', confidence: 95 });

      const map = builder.build();
      expect(map.wafDetected).not.toBeNull();
      expect(map.wafDetected?.name).toBe('Cloudflare');
    });
  });

  describe('build', () => {
    it('should produce a valid AssetMap', () => {
      builder.addSubdomain({
        name: 'test.example.com',
        ips: ['1.2.3.4'],
        cnames: [],
        status: 'resolved',
        technologies: [],
      });

      const map = builder.build();
      expect(map.domain).toBe('example.com');
      expect(map.subdomains).toHaveLength(1);
      expect(map.ports).toHaveLength(0);
      expect(map.endpoints).toHaveLength(0);
    });
  });

  describe('getInjectableEndpoints', () => {
    it('should return only endpoints with parameters', () => {
      builder.addEndpoint({
        url: 'https://example.com/static',
        method: 'GET',
        params: [],
        source: 'crawl',
      });
      builder.addEndpoint({
        url: 'https://example.com/search?q=test',
        method: 'GET',
        params: [{ name: 'q', type: 'query' }],
        source: 'crawl',
      });

      const injectable = builder.getInjectableEndpoints();
      expect(injectable).toHaveLength(1);
      expect(injectable[0].url).toContain('search');
    });
  });

  describe('getDanglingCNAMEs', () => {
    it('should identify subdomains with unresolved CNAMEs', () => {
      builder.addSubdomain({
        name: 'old.example.com',
        ips: [],
        cnames: ['something.azurewebsites.net'],
        status: 'unresolved',
        technologies: [],
      });
      builder.addSubdomain({
        name: 'active.example.com',
        ips: ['1.2.3.4'],
        cnames: [],
        status: 'resolved',
        technologies: [],
      });

      const dangling = builder.getDanglingCNAMEs();
      expect(dangling).toHaveLength(1);
      expect(dangling[0].name).toBe('old.example.com');
    });
  });

  describe('getSummary', () => {
    it('should return a readable summary string', () => {
      builder.addSubdomain({
        name: 'api.example.com',
        ips: ['1.2.3.4'],
        cnames: [],
        status: 'resolved',
        technologies: [],
      });
      builder.addPort({ host: 'example.com', port: 443, service: 'https', state: 'open' });

      const summary = builder.getSummary();
      expect(summary).toContain('example.com');
      expect(summary).toContain('1');
    });
  });
});
