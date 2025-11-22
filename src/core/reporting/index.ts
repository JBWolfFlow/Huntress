/**
 * Reporting Module
 * 
 * Exports HackerOne API client, PoC generator, and report templates
 */

export { HackerOneAPI, type H1Config, type H1Report, type H1Response } from './h1_api';
export { PoCGenerator, type PoC } from './poc_generator';
export { REPORT_TEMPLATES, fillTemplate } from './templates';