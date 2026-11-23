export function repoResponseOrder(findings: readonly { category: string; title: string; severity: string }[]) {
  const steps: string[] = [];
  if (findings.some((finding) => finding.category === "secrets" || finding.category === "environment" && /credential committed/i.test(finding.title))) {
    steps.push("Revoke or rotate confirmed exposed credentials.", "Remove the exposed values from the current tree and Git history.");
  }
  const routeCategories = [
    ["authorization", "authorization"], ["billing", "payment"], ["webhooks", "webhook"],
  ].filter(([category]) => findings.some((finding) => finding.category === category)).map(([, label]) => label);
  if (routeCategories.length) steps.push("Review " + new Intl.ListFormat("en").format(routeCategories) + " findings. Fix confirmed issues before deployment.");
  if (findings.some((finding) => finding.category === "dependencies")) steps.push("Upgrade affected dependencies and check the resolved lockfile.");
  if (findings.some((finding) => !["secrets", "environment", "authorization", "billing", "webhooks", "dependencies"].includes(finding.category))) steps.push("Verify the remaining findings and fix confirmed issues.");
  steps.push("Rescan the repository and deployed website after changes.");
  return steps;
}
