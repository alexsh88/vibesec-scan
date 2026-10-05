// Static, deterministic per-SecretType text used to build credential Findings. Nothing here depends
// on a particular candidate (file, liveness, history, …) — that context is layered on in
// credentialsAnalyzer.ts (e.g. the inHistoryOnly note appended to `explanation`).

import type { Severity } from '@vibesec/shared';
import type { SecretType } from './rules';

export type CredentialTemplate = {
  title: string;
  baseSeverity: Severity;
  explanation: string;
  impact: string;
  remediation: { summary: string };
};

/**
 * Builds the standard four-part remediation summary (revoke/rotate → remove from code → load from
 * env/secrets manager → purge history) for a given provider/credential description. Rotation is the
 * step that actually neutralizes the exposure, which is why it always comes first and why the
 * history-purge guidance is included unconditionally: a finding scoped to the current tree today can
 * easily be in an earlier commit the detector didn't scan this run.
 */
function remediationFor(credential: string, provider: string): { summary: string } {
  return {
    summary: [
      `Revoke/rotate this ${credential} immediately in the ${provider} dashboard or API — rotation is what actually neutralizes the exposure.`,
      'Remove the value from the codebase (replace it with a reference, never a literal).',
      'Load it at runtime from environment variables or a secrets manager (e.g. AWS Secrets Manager, HashiCorp Vault, Doppler).',
      'If it also appears in git history, purge it with `git filter-repo` or the BFG Repo-Cleaner after rotating — deleting the current line does not remove it from past commits.',
    ].join(' '),
  };
}

export const CREDENTIAL_TEMPLATES: Record<SecretType, CredentialTemplate> = {
  'github-token': {
    title: 'GitHub access token',
    baseSeverity: 'high',
    explanation: 'A GitHub personal access token, fine-grained token, or GitHub App/OAuth token was detected by its `gh[pousr]_`/`github_pat_` prefix.',
    impact: 'Grants code and repository access under the token\'s permissions — enabling malicious commits, release tampering, exfiltration of other secrets stored in CI, and a supply-chain compromise of anything this repository builds, publishes, or deploys.',
    remediation: remediationFor('GitHub token', 'GitHub (Settings → Developer settings)'),
  },
  'aws-access-key': {
    title: 'AWS access key',
    baseSeverity: 'high',
    explanation: 'An AWS access key id (`AKIA`/`ASIA` prefix) was detected, optionally paired with a nearby 40-character secret access key.',
    impact: 'Grants programmatic access to the associated AWS account — enabling data exfiltration from S3/RDS/DynamoDB, provisioning resources for cryptomining or further attacks, and direct cost abuse, bounded only by the key\'s IAM permissions.',
    remediation: remediationFor('AWS access key pair', 'AWS IAM console'),
  },
  'stripe-secret-key': {
    title: 'Stripe live secret key',
    baseSeverity: 'critical',
    explanation: 'A Stripe live-mode secret key (`sk_live_` prefix) was detected.',
    impact: 'Full live-mode API access to the Stripe account — creating and capturing charges, issuing refunds, reading customer PII and payment history, and changing account configuration.',
    remediation: remediationFor('Stripe live secret key', 'Stripe Dashboard (Developers → API keys)'),
  },
  'stripe-restricted-key': {
    title: 'Stripe restricted API key',
    baseSeverity: 'high',
    explanation: 'A Stripe live-mode restricted key (`rk_live_` prefix) was detected.',
    impact: 'Live-mode API access scoped to whatever permissions the key was issued with — still enough for charges, refunds, or exposure of customer data within that scope.',
    remediation: remediationFor('Stripe restricted key', 'Stripe Dashboard (Developers → API keys)'),
  },
  'stripe-test-key': {
    title: 'Stripe test-mode secret key',
    baseSeverity: 'low',
    explanation: 'A Stripe test-mode secret key (`sk_test_` prefix) was detected.',
    impact: 'Test-mode only — cannot move real funds or access live customer data, but can still expose the account\'s test configuration and consume API quota; the risk rises sharply if it is mistaken for (or reused as) a live key.',
    remediation: remediationFor('Stripe test secret key', 'Stripe Dashboard (Developers → API keys)'),
  },
  'slack-token': {
    title: 'Slack API token',
    baseSeverity: 'high',
    explanation: 'A Slack bot/user/app token (`xox[baprs]-` prefix) was detected.',
    impact: 'Grants access to the Slack workspace scoped to the token\'s OAuth scopes — reading private channel content and DMs, posting as the bot/user, or exfiltrating workspace member and message data depending on scope.',
    remediation: remediationFor('Slack token', 'Slack app management page (api.slack.com/apps)'),
  },
  'slack-webhook': {
    title: 'Slack incoming webhook URL',
    baseSeverity: 'medium',
    explanation: 'A Slack incoming-webhook URL (hooks.slack.com/services/...) was detected.',
    impact: 'Allows anyone holding the URL to post arbitrary messages into the destination Slack channel — enabling phishing, spam, or impersonation inside the workspace; it cannot read any data.',
    remediation: remediationFor('Slack webhook URL', 'Slack app management page (api.slack.com/apps)'),
  },
  'openai-api-key': {
    title: 'OpenAI API key',
    baseSeverity: 'high',
    explanation: 'An OpenAI API key (`sk-...T3BlbkFJ...` legacy or `sk-proj-` prefix) was detected.',
    impact: 'Grants API access billed to the account owner — enabling large-scale cost abuse and, where the account has fine-tuning or org-level access, exposure of proprietary prompts, fine-tuned models, or usage data.',
    remediation: remediationFor('OpenAI API key', 'OpenAI Platform (API keys page)'),
  },
  'anthropic-api-key': {
    title: 'Anthropic API key',
    baseSeverity: 'high',
    explanation: 'An Anthropic API key (`sk-ant-api`/`sk-ant-admin` prefix) was detected.',
    impact: 'Grants Claude API access billed to the account owner — enabling large-scale cost abuse and misuse of the account\'s rate limits, model access, and (for admin keys) organization settings.',
    remediation: remediationFor('Anthropic API key', 'Anthropic Console (API keys page)'),
  },
  'google-api-key': {
    title: 'Google API key',
    baseSeverity: 'medium',
    explanation: 'A Google API key (`AIza` prefix) was detected.',
    impact: 'Grants access to whichever Google Cloud, Maps, or Firebase APIs the key is enabled for — cost abuse, quota exhaustion, or, if unrestricted by API/referrer, access to any service enabled on that project.',
    remediation: remediationFor('Google API key', 'Google Cloud Console (APIs & Services → Credentials)'),
  },
  'sendgrid-api-key': {
    title: 'SendGrid API key',
    baseSeverity: 'high',
    explanation: 'A SendGrid API key (`SG.` prefix) was detected.',
    impact: 'Grants the ability to send email as the account\'s verified senders/domains — enabling phishing and spam campaigns that damage sender reputation and deliverability, plus access to stored contact lists and email activity logs.',
    remediation: remediationFor('SendGrid API key', 'Twilio SendGrid Settings → API Keys'),
  },
  'twilio-api-key': {
    title: 'Twilio API key',
    baseSeverity: 'high',
    explanation: 'A Twilio API key (`SK` + 32 hex chars) was detected.',
    impact: 'Grants the ability to send SMS/voice traffic and read call/message logs billed to the account — enabling toll fraud and smishing campaigns, and exposing customer phone numbers and message content.',
    remediation: remediationFor('Twilio API key', 'Twilio Console (Account → API keys & tokens)'),
  },
  'private-key': {
    title: 'Private key',
    baseSeverity: 'high',
    explanation: 'A PEM-encoded private key block (`-----BEGIN ... PRIVATE KEY-----`) was detected.',
    impact: 'Depending on its use, allows SSH or server access, TLS/code-signing impersonation, or decryption of data protected by the matching public key — a direct path to full compromise of whatever system trusts it.',
    remediation: remediationFor('private key', 'the system that trusts the matching public key (re-issue a new keypair)'),
  },
  jwt: {
    title: 'Signed JWT',
    baseSeverity: 'medium',
    explanation: 'A signed JWT (three-part `eyJ...` token) with a decodable, non-public role claim was detected.',
    impact: 'Grants whatever access the token\'s claims authorize for as long as it remains valid — session hijacking or privilege misuse if the signing key or audience trusts this token without further checks.',
    remediation: remediationFor('JWT', 'the issuing service (invalidate the session/signing key)'),
  },
  'supabase-service-role': {
    title: 'Supabase service_role key',
    baseSeverity: 'critical',
    explanation: 'A Supabase JWT whose decoded `role` claim is `service_role` was detected.',
    impact: 'Bypasses Row Level Security entirely — full read/write access to every table in the Supabase project\'s Postgres database, equivalent to a database superuser.',
    remediation: remediationFor('Supabase service_role key', 'Supabase Dashboard (Project Settings → API)'),
  },
  'database-url': {
    title: 'Database connection string',
    baseSeverity: 'high',
    explanation: 'A database connection URL (postgres/mysql/mongodb/redis/amqp) with an embedded, non-placeholder password was detected.',
    impact: 'Grants direct network access to the database with the embedded credentials — full read/write (and often schema) access to production data, bounded only by that account\'s grants.',
    remediation: remediationFor('database password', 'the database server or managed-database provider console'),
  },
  'generic-secret': {
    title: 'Generic credential',
    baseSeverity: 'medium',
    explanation: 'A high-entropy value assigned to a password/secret/token/key-like name was detected by generic pattern and entropy heuristics (no specific provider format matched).',
    impact: 'The exact impact depends on what the value authenticates to, but a high-entropy credential found in code or config is assumed to grant some privileged access or service until proven otherwise.',
    remediation: remediationFor('credential', 'whichever system it authenticates to'),
  },
};
