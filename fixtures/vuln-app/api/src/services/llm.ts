// Stub: in the real app this calls out to a hosted model. Kept trivial here since the fixture
// only needs to demonstrate the prompt-injection and eval-of-model-output sinks downstream.
export async function callModel(systemPrompt: string, userMessage: string): Promise<string> {
  return `echo: ${systemPrompt.length > 0 ? userMessage : userMessage}`;
}
