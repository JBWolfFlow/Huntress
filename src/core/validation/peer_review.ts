/**
 * Peer Review System
 *
 * After automated validation, runs a second LLM review using a different
 * model instance. If the peer reviewer disagrees with the finding,
 * it's flagged for human review.
 */

import type { ModelProvider, ChatMessage } from '../providers/types';
import type { ReactFinding } from '../engine/react_loop';
import type { ValidationResult } from './validator';

export interface PeerReviewResult {
  findingId: string;
  agrees: boolean;
  confidence: number;
  reasoning: string;
  suggestedSeverity?: string;
  flaggedForHumanReview: boolean;
  reviewerModel: string;
}

/**
 * Run peer review on a validated finding.
 * Uses a different model or model instance to independently assess the finding.
 */
export async function peerReview(
  finding: ReactFinding,
  validation: ValidationResult,
  provider: ModelProvider,
  model: string
): Promise<PeerReviewResult> {
  const prompt = `You are a senior security researcher performing peer review on a bug bounty finding. Your job is to critically evaluate whether this is a REAL, EXPLOITABLE vulnerability or a false positive.

## Finding
- **Title:** ${finding.title}
- **Type:** ${finding.vulnerabilityType}
- **Severity:** ${finding.severity}
- **Target:** ${finding.target}
- **Description:** ${finding.description}
- **Impact:** ${finding.impact}
- **Confidence:** ${finding.confidence}%

## Evidence
${finding.evidence.map((e, i) => `${i + 1}. ${e}`).join('\n')}

## Reproduction Steps
${finding.reproductionSteps.map((s, i) => `${i + 1}. ${s}`).join('\n')}

## Automated Validation
- **Confirmed:** ${validation.confirmed}
- **Validator:** ${validation.validatorUsed}
- **Validation Confidence:** ${validation.confidence}%
${validation.evidence.map(e => `- ${e.description}: ${e.data.substring(0, 200)}`).join('\n')}

## Your Assessment
Evaluate this finding critically:
1. Is the evidence sufficient to prove exploitability?
2. Could this be a false positive? What alternative explanations exist?
3. Is the severity assessment accurate?
4. Would you submit this to HackerOne?

Respond with a JSON object:
{
  "agrees": true/false,
  "confidence": 0-100,
  "reasoning": "Your detailed assessment",
  "suggestedSeverity": "info|low|medium|high|critical",
  "wouldSubmit": true/false
}

Return ONLY the JSON.`;

  const messages: ChatMessage[] = [{ role: 'user', content: prompt }];

  try {
    const response = await provider.sendMessage(messages, {
      model,
      maxTokens: 1024,
      temperature: 0.3,
      systemPrompt: 'You are a critical peer reviewer for security findings. Be skeptical and thorough. Only agree with findings that have strong evidence.',
    });

    const jsonMatch = response.content.match(/\{[\s\S]*\}/);
    if (!jsonMatch) {
      return {
        findingId: finding.id,
        agrees: false,
        confidence: 50,
        reasoning: 'Failed to parse peer review response',
        flaggedForHumanReview: true,
        reviewerModel: model,
      };
    }

    const parsed = JSON.parse(jsonMatch[0]);

    const agrees = parsed.agrees === true;
    const disagreement = !agrees && validation.confirmed;

    return {
      findingId: finding.id,
      agrees,
      confidence: parsed.confidence ?? 50,
      reasoning: parsed.reasoning ?? 'No reasoning provided',
      suggestedSeverity: parsed.suggestedSeverity,
      flaggedForHumanReview: disagreement,
      reviewerModel: model,
    };
  } catch (error) {
    return {
      findingId: finding.id,
      agrees: false,
      confidence: 0,
      reasoning: `Peer review failed: ${error instanceof Error ? error.message : String(error)}`,
      flaggedForHumanReview: true,
      reviewerModel: model,
    };
  }
}

export default peerReview;
