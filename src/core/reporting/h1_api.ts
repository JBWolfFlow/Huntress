/**
 * HackerOne API Integration (Phase 4)
 *
 * One-Click Submission System:
 * - Submit reports to HackerOne
 * - Upload attachments (videos, screenshots, logs)
 * - Track submission status
 * - Update reports
 * - Error handling and retry logic
 *
 * NOTE: Runs inside Tauri WebView — no Node.js APIs (fs, path).
 * File operations use Tauri invoke() commands.
 */

import axios, { AxiosInstance, AxiosError } from 'axios';
import { invoke } from '@tauri-apps/api/core';
import type { DuplicateScore } from '../../utils/duplicate_checker';

// ─── Browser-compatible path helpers (replaces Node.js 'path') ────────────

/** Extract the filename from a path string (replaces path.basename) */
function basename(filePath: string): string {
  const parts = filePath.replace(/\\/g, '/').split('/');
  return parts[parts.length - 1] || filePath;
}

/** Extract the file extension from a filename (replaces path.extname) */
function extname(filename: string): string {
  const dot = filename.lastIndexOf('.');
  return dot > 0 ? filename.slice(dot) : '';
}

export interface H1Report {
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  suggestedBounty: { min: number; max: number };
  description: string;
  impact: string;
  steps: string[];
  proof: {
    video?: string;
    screenshots?: string[];
    logs?: string[];
  };
  duplicateCheck?: DuplicateScore;
  severityJustification?: string[];
  cvssScore?: number;
  /** S3: CVSS 3.1 vector string (e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N) */
  cvssVector?: string;
  weaknessId?: string;
  /** RQ3: Formatted HTTP evidence markdown (request/response code blocks) */
  httpEvidence?: string;
  /** RQ5: Executable reproduction commands (curl, Python) */
  quickReproduction?: string;
}

export interface Attachment {
  type: 'video' | 'screenshot' | 'log' | 'other';
  path: string;
  filename?: string;
  contentType?: string;
}

export interface SubmissionResult {
  success: boolean;
  reportId?: string;
  reportUrl?: string;
  status?: string;
  message?: string;
  error?: string;
  attachmentIds?: string[];
}

export interface ReportStatus {
  id: string;
  state: string;
  title: string;
  createdAt: string;
  triageAt?: string;
  closedAt?: string;
  disclosedAt?: string;
  bountyAwarded?: number;
  severity?: string;
  lastActivityAt?: string;
}

export interface H1ApiConfig {
  username: string;
  apiToken: string;
  baseUrl?: string;
  timeout?: number;
  maxRetries?: number;
  retryDelay?: number;
}

export class HackerOneAPI {
  private client: AxiosInstance;
  private config: H1ApiConfig;
  private maxRetries: number;
  private retryDelay: number;

  constructor(config: H1ApiConfig) {
    this.config = {
      baseUrl: 'https://api.hackerone.com/v1',
      timeout: 30000,
      maxRetries: 3,
      retryDelay: 2000,
      ...config,
    };

    this.maxRetries = this.config.maxRetries!;
    this.retryDelay = this.config.retryDelay!;

    // Create axios instance with authentication
    this.client = axios.create({
      baseURL: this.config.baseUrl,
      timeout: this.config.timeout,
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      auth: {
        username: this.config.username,
        password: this.config.apiToken,
      },
    });

    // Add response interceptor for error handling
    this.client.interceptors.response.use(
      (response) => response,
      (error) => this.handleApiError(error)
    );
  }

  /**
   * Submit a report to HackerOne
   */
  async submitReport(params: {
    programHandle: string;
    report: H1Report;
    attachments?: Attachment[];
  }): Promise<SubmissionResult> {
    const { programHandle, report, attachments } = params;

    try {
      console.log(`Submitting report to ${programHandle}...`);

      // 1. Create the report
      const reportData = this.formatReportData(report, programHandle);
      const createResponse = await this.retryRequest(() =>
        this.client.post('/reports', reportData)
      );

      const reportId = createResponse.data.data.id;
      const reportUrl = `https://hackerone.com/reports/${reportId}`;

      console.log(`Report created: ${reportId}`);

      // 2. Upload attachments if provided
      const attachmentIds: string[] = [];
      if (attachments && attachments.length > 0) {
        console.log(`Uploading ${attachments.length} attachments...`);

        for (const attachment of attachments) {
          try {
            const attachmentId = await this.uploadAttachment(attachment);
            attachmentIds.push(attachmentId);
            console.log(`Uploaded: ${basename(attachment.path)}`);
          } catch (error) {
            console.error(`Failed to upload ${attachment.path}:`, error);
          }
        }

        // 3. Attach files to report
        if (attachmentIds.length > 0) {
          await this.attachFilesToReport(reportId, attachmentIds);
          console.log(`Attached ${attachmentIds.length} files to report`);
        }
      }

      // 4. Get final report status
      const status = await this.getReportStatus(reportId);

      return {
        success: true,
        reportId,
        reportUrl,
        status: status.state,
        message: `Report submitted successfully to ${programHandle}`,
        attachmentIds,
      };
    } catch (error) {
      console.error('Report submission failed:', error);
      return {
        success: false,
        error: this.extractErrorMessage(error),
        message: 'Failed to submit report',
      };
    }
  }

  /**
   * Upload an attachment to HackerOne.
   *
   * Reads the file via Tauri IPC (no Node.js fs), converts to a Blob,
   * and uploads via the browser-native FormData API.
   */
  async uploadAttachment(attachment: Attachment): Promise<string> {
    try {
      // Check if file exists via Tauri
      const exists = await invoke<boolean>('file_exists', { path: attachment.path });
      if (!exists) {
        throw new Error(`File not found: ${attachment.path}`);
      }

      // Read file as base64-encoded binary via Tauri to avoid UTF-8 corruption
      const base64Content = await invoke<string>('read_file_binary', { path: attachment.path });

      const filename = attachment.filename || basename(attachment.path);
      const contentType = attachment.contentType || this.getContentType(filename);

      // Decode base64 to binary Uint8Array for proper blob creation
      const binaryStr = atob(base64Content);
      const bytes = new Uint8Array(binaryStr.length);
      for (let i = 0; i < binaryStr.length; i++) {
        bytes[i] = binaryStr.charCodeAt(i);
      }
      const blob = new Blob([bytes], { type: contentType });

      // Use browser-native FormData
      const formData = new FormData();
      formData.append('file', blob, filename);

      // Upload to HackerOne
      const response = await this.retryRequest(() =>
        this.client.post('/attachments', formData, {
          headers: {
            'Content-Type': 'multipart/form-data',
          },
          maxBodyLength: Infinity,
          maxContentLength: Infinity,
        })
      );

      return response.data.data.id;
    } catch (error) {
      throw new Error(`Failed to upload attachment: ${this.extractErrorMessage(error)}`);
    }
  }

  /**
   * Attach uploaded files to a report
   */
  private async attachFilesToReport(reportId: string, attachmentIds: string[]): Promise<void> {
    try {
      await this.retryRequest(() =>
        this.client.post(`/reports/${reportId}/attachments`, {
          data: {
            type: 'report-attachment',
            relationships: {
              attachments: {
                data: attachmentIds.map(id => ({
                  type: 'attachment',
                  id,
                })),
              },
            },
          },
        })
      );
    } catch (error) {
      throw new Error(`Failed to attach files to report: ${this.extractErrorMessage(error)}`);
    }
  }

  /**
   * Get report status
   */
  async getReportStatus(reportId: string): Promise<ReportStatus> {
    try {
      const response = await this.retryRequest(() =>
        this.client.get(`/reports/${reportId}`)
      );

      const data = response.data.data;
      const attributes = data.attributes;

      return {
        id: data.id,
        state: attributes.state,
        title: attributes.title,
        createdAt: attributes.created_at,
        triageAt: attributes.triaged_at,
        closedAt: attributes.closed_at,
        disclosedAt: attributes.disclosed_at,
        bountyAwarded: attributes.bounty_awarded_at ? attributes.bounty_amount : undefined,
        severity: attributes.severity?.rating,
        lastActivityAt: attributes.last_activity_at,
      };
    } catch (error) {
      throw new Error(`Failed to get report status: ${this.extractErrorMessage(error)}`);
    }
  }

  /**
   * Update an existing report
   */
  async updateReport(reportId: string, updates: Partial<H1Report>): Promise<void> {
    try {
      const updateData: Record<string, unknown> = {
        data: {
          type: 'report',
          id: reportId,
          attributes: {} as Record<string, unknown>,
        },
      };

      const attrs = (updateData.data as Record<string, unknown>).attributes as Record<string, unknown>;

      // Map updates to API format
      if (updates.title) {
        attrs.title = updates.title;
      }
      if (updates.description) {
        attrs.vulnerability_information = updates.description;
      }
      if (updates.severity) {
        attrs.severity = {
          rating: updates.severity,
        };
      }

      await this.retryRequest(() =>
        this.client.patch(`/reports/${reportId}`, updateData)
      );

      console.log(`Report ${reportId} updated successfully`);
    } catch (error) {
      throw new Error(`Failed to update report: ${this.extractErrorMessage(error)}`);
    }
  }

  /**
   * Add a comment to a report
   */
  async addComment(reportId: string, comment: string): Promise<void> {
    try {
      await this.retryRequest(() =>
        this.client.post(`/reports/${reportId}/activities`, {
          data: {
            type: 'activity-comment',
            attributes: {
              message: comment,
            },
          },
        })
      );

      console.log(`Comment added to report ${reportId}`);
    } catch (error) {
      throw new Error(`Failed to add comment: ${this.extractErrorMessage(error)}`);
    }
  }

  /**
   * Get program details
   */
  async getProgramDetails(programHandle: string): Promise<Record<string, unknown>> {
    try {
      const response = await this.retryRequest(() =>
        this.client.get(`/programs/${programHandle}`)
      );

      return response.data.data;
    } catch (error) {
      throw new Error(`Failed to get program details: ${this.extractErrorMessage(error)}`);
    }
  }

  /**
   * Format report data for HackerOne API
   */
  private formatReportData(report: H1Report, programHandle: string): Record<string, unknown> {
    // Build vulnerability information markdown
    let vulnerabilityInfo = `# ${report.title}\n\n`;
    vulnerabilityInfo += `## Description\n${report.description}\n\n`;
    vulnerabilityInfo += `## Impact\n${report.impact}\n\n`;
    vulnerabilityInfo += `## Steps to Reproduce\n`;
    report.steps.forEach((step, index) => {
      vulnerabilityInfo += `${index + 1}. ${step}\n`;
    });

    // Add severity justification if available
    if (report.severityJustification && report.severityJustification.length > 0) {
      vulnerabilityInfo += `\n## Severity Justification\n`;
      report.severityJustification.forEach(reason => {
        vulnerabilityInfo += `- ${reason}\n`;
      });
    }

    // Add CVSS score if available
    if (report.cvssScore) {
      vulnerabilityInfo += `\n## CVSS Score\n${report.cvssScore}\n`;
    }

    // Add duplicate check info if available
    if (report.duplicateCheck) {
      vulnerabilityInfo += `\n## Duplicate Check\n`;
      vulnerabilityInfo += `- Overall Score: ${report.duplicateCheck.overall}%\n`;
      vulnerabilityInfo += `- Recommendation: ${report.duplicateCheck.recommendation}\n`;
    }

    return {
      data: {
        type: 'report',
        attributes: {
          title: report.title,
          vulnerability_information: vulnerabilityInfo,
          severity_rating: report.severity,
          weakness_id: report.weaknessId,
        },
        relationships: {
          program: {
            data: {
              type: 'program',
              attributes: {
                handle: programHandle,
              },
            },
          },
        },
      },
    };
  }

  /**
   * Retry request with exponential backoff
   */
  private async retryRequest<T>(
    requestFn: () => Promise<T>,
    retries: number = this.maxRetries
  ): Promise<T> {
    try {
      return await requestFn();
    } catch (error) {
      if (retries > 0 && this.isRetryableError(error)) {
        const delay = this.retryDelay * (this.maxRetries - retries + 1);
        console.log(`Retrying in ${delay}ms... (${retries} retries left)`);
        await this.sleep(delay);
        return this.retryRequest(requestFn, retries - 1);
      }
      throw error;
    }
  }

  /**
   * Check if error is retryable
   */
  private isRetryableError(error: unknown): boolean {
    const axiosErr = error as { response?: { status: number } };
    if (!axiosErr.response) {
      // Network errors are retryable
      return true;
    }

    const status = axiosErr.response.status;
    // Retry on 429 (rate limit), 500, 502, 503, 504
    return status === 429 || (status >= 500 && status <= 504);
  }

  /**
   * Handle API errors
   */
  private handleApiError(error: AxiosError): Promise<never> {
    if (error.response) {
      const status = error.response.status;
      const data = error.response.data as Record<string, unknown> | undefined;

      let message = `HackerOne API error (${status})`;

      if (data?.errors && Array.isArray(data.errors)) {
        message += `: ${(data.errors as Array<{ detail?: string; title?: string }>).map(e => e.detail || e.title).join(', ')}`;
      } else if (data?.error) {
        message += `: ${data.error}`;
      }

      console.error(message);
      error.message = message;
    } else if (error.request) {
      error.message = 'No response from HackerOne API - check network connection';
      console.error(error.message);
    }

    return Promise.reject(error);
  }

  /**
   * Extract error message from error object
   */
  private extractErrorMessage(error: unknown): string {
    const axiosErr = error as { response?: { data?: { errors?: Array<{ detail?: string; title?: string }> } }; message?: string };
    if (axiosErr.response?.data?.errors) {
      return axiosErr.response.data.errors
        .map(e => e.detail || e.title)
        .join(', ');
    }
    return axiosErr.message || 'Unknown error';
  }

  /**
   * Get content type from filename
   */
  private getContentType(filename: string): string {
    const ext = extname(filename).toLowerCase();
    const contentTypes: Record<string, string> = {
      '.mp4': 'video/mp4',
      '.webm': 'video/webm',
      '.avi': 'video/x-msvideo',
      '.mov': 'video/quicktime',
      '.png': 'image/png',
      '.jpg': 'image/jpeg',
      '.jpeg': 'image/jpeg',
      '.gif': 'image/gif',
      '.txt': 'text/plain',
      '.log': 'text/plain',
      '.cast': 'application/json',
      '.json': 'application/json',
      '.pdf': 'application/pdf',
    };
    return contentTypes[ext] || 'application/octet-stream';
  }

  /**
   * Sleep utility
   */
  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Test API connection
   */
  async testConnection(): Promise<boolean> {
    try {
      await this.client.get('/me');
      console.log('HackerOne API connection successful');
      return true;
    } catch (error) {
      console.error('HackerOne API connection failed:', this.extractErrorMessage(error));
      return false;
    }
  }

  /**
   * Get user information
   */
  async getUserInfo(): Promise<Record<string, unknown>> {
    try {
      const response = await this.client.get('/me');
      return response.data.data;
    } catch (error) {
      throw new Error(`Failed to get user info: ${this.extractErrorMessage(error)}`);
    }
  }
}

export default HackerOneAPI;
