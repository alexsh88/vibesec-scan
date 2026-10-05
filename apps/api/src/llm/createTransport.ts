import type { Config } from '../config';
import { AnthropicTransport } from './anthropicTransport';
import { MockTransport, RecordingTransport } from './mockTransport';
import type { LlmTransport } from './transport';

/** mock: recordings → responders → schema fakes (no key). live: Anthropic API. record: live + write recordings. */
export function createTransport(config: Config): LlmTransport {
  if (config.scanMode === 'mock') return new MockTransport({ recordingsDir: config.llmRecordingsDir });
  const live = AnthropicTransport.create(config.anthropicApiKey!, config.llmTimeoutMs);
  return config.scanMode === 'record' ? new RecordingTransport(live, config.llmRecordingsDir) : live;
}
