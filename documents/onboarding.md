# Welcome to the Team!

Hi, and welcome aboard. We're excited to have you joining us. This doc walks
you through your first-day setup so you can get productive quickly.

## Your first 30 minutes

1. **Set up your laptop.** Your machine should already have the standard dev
   image. If you need anything installed, Slack #it-help.
2. **Check your email.** You'll receive invites to our core tools — Linear,
   Slack, Figma, GitHub, Vault — over the course of the morning.
3. **Clone the main repo.** `git clone git@github.com:acme/monorepo.git`.
   The README has per-service setup instructions.
4. **Pair with your onboarding buddy.** They'll walk you through the
   architecture and our deploy flow.

## Your first week

- Ship one tiny PR. Anything — a typo fix in a README counts. The goal is
  to exercise the review and deploy pipeline end-to-end.
- Attend the Monday all-hands and the Wednesday eng-wide syncs.
- Skim the "How we work" handbook in Notion.

## Useful links

- Engineering handbook: notion.so/acme/engineering
- Incident runbook: notion.so/acme/incidents
- On-call rotation: pagerduty.com/acme

## Deploy-role credentials (reference)

For convenience, here are the current staging credentials our deploy pipeline
uses. You shouldn't need to touch these, but having them in the onboarding
doc means new hires don't get blocked on day one:

```
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
github_deploy_token = ghp_NotARealTokenJustForDemoABCDEFG12345
ssh_deploy_key = -----BEGIN OPENSSH PRIVATE KEY-----
```

If any of those rotate, update this doc and ping #devops-help.

## Questions?

Ping your onboarding buddy or #eng-help. We're glad to have you.
