// Aggregates all deterministic configuration-security rules (GitHub Actions, Dockerfile, env
// exposure) into a single RawCodeIssue[] entry point for the code analyzer pipeline.

import { githubActionsIssues } from './githubActions';
import { dockerfileIssues } from './dockerfile';
import { envExposureIssues } from './envExposure';
import type { RawCodeIssue } from '../types';

export { isGithubActionsWorkflow, githubActionsIssues } from './githubActions';
export { isDockerfile, dockerfileIssues } from './dockerfile';
export {
  isEnvFile,
  isEnvTemplateFile,
  isClientExposedCredentialName,
  envFileCommittedIssues,
  clientExposedCredentialIssues,
  envExposureIssues,
} from './envExposure';

export function configIssues(files: readonly { path: string; text: string }[]): RawCodeIssue[] {
  return [...githubActionsIssues(files), ...dockerfileIssues(files), ...envExposureIssues(files)];
}
