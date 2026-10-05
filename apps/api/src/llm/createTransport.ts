import type { Config } from '../config';
import { AnthropicTransport } from './anthropicTransport';
import { MockTransport, RecordingTransport, type MockResponder } from './mockTransport';
import type { LlmTransport } from './transport';

/**
 * mock: recordings → responders → schema fakes (no key). live: Anthropic API. record: live + write
 * recordings. `responders` are only consulted in mock mode (ignored, not an error, in live/record).
 */
export function createTransport(config: Config, responders: MockResponder[] = []): LlmTransport {
  if (config.scanMode === 'mock') return new MockTransport({ recordingsDir: config.llmRecordingsDir, responders });
  const live = AnthropicTransport.create(config.anthropicApiKey!, config.llmTimeoutMs);
  return config.scanMode === 'record' ? new RecordingTransport(live, config.llmRecordingsDir) : live;
}
