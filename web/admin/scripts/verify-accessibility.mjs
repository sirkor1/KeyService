import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');

const checks = [
  ['Dialog traps Tab inside the modal', 'src/components/Dialog.tsx', "event.key !== 'Tab'"],
  ['Dialog restores the invoking focus', 'src/components/Dialog.tsx', 'returnFocus.current.focus()'],
  ['Dialog lifecycle is not reset by inline callbacks', 'src/components/Dialog.tsx', 'onCloseRef.current = onClose'],
  ['Dialog recovers focus that left the modal', 'src/components/Dialog.tsx', '!ref.current?.contains(document.activeElement)'],
  ['Reverse Tab restores focus at the end of the modal', 'src/components/Dialog.tsx', 'event.shiftKey ? last : first'],
  ['Busy confirmation cannot be dismissed', 'src/components/Dialog.tsx', 'closeDisabled={busy}'],
  ['Interactive table rows support Enter', 'src/components/Table.tsx', "event.key === 'Enter'"],
  ['Interactive table rows receive tab focus', 'src/components/Table.tsx', 'tabIndex={href ? 0 : undefined}'],
  ['Empty table result is announced', 'src/components/Table.tsx', 'role="status"'],
  ['Loading status is announced atomically', 'src/components/Spinner.tsx', 'aria-atomic="true"'],
  ['Keyboard focus remains visibly styled', 'src/styles/ds/styles.css', ':focus-visible'],
  ['Passcode form is busy while creating', 'src/pages/PassCodesPage.tsx', 'aria-busy={create.isPending}'],
  ['Passcode input is locked while creating', 'src/pages/PassCodesPage.tsx', 'disabled={create.isPending}'],
  ['SSH fields are marked busy while testing', 'src/pages/add-server/Steps.tsx', 'aria-busy={testing}'],
  ['SSH credential editing is locked while testing', 'src/pages/add-server/Steps.tsx', 'disabled={testing}'],
  ['SSH test is invalidated by connection changes', 'src/pages/add-server/AddServerPage.tsx', 'connectionFingerprint'],
  ['SSH test clears stale result before a new request', 'src/pages/add-server/AddServerPage.tsx', 'onMutate: () => setTest(null)'],
  ['Wizard navigation is locked while SSH test runs', 'src/pages/add-server/AddServerPage.tsx', 'disabled={connectionTest.isPending || install.isPending || Boolean(jobId)}'],
];

const routeChecks = [
  ['Servers use exclusive query states', 'src/pages/ServersPage.tsx'],
  ['Keys use exclusive query states', 'src/pages/KeysPage.tsx'],
  ['Users use exclusive query states', 'src/pages/UsersPage.tsx'],
  ['Passcodes use exclusive query states', 'src/pages/PassCodesPage.tsx'],
  ['Logs use exclusive query states', 'src/pages/LogsPage.tsx'],
  ['Server detail keys use exclusive query states', 'src/pages/ServerDetailPage.tsx', 'keys'],
];

const exclusiveQueryState = (queryName) => new RegExp(
  `${queryName}\\.isPending\\s*\\?\\s*(?:\\(\\s*)?<Spinner[^>]*\\/>\\s*\\)?\\s*:\\s*${queryName}\\.isError\\s*\\?`,
);

let failed = false;
for (const [name, file, needle] of checks) {
  const text = readFileSync(resolve(root, file), 'utf8');
  if (text.includes(needle)) continue;

  failed = true;
  console.error(`FAIL: ${name} (${file})`);
}

for (const [name, file, queryName = 'query'] of routeChecks) {
  const text = readFileSync(resolve(root, file), 'utf8');
  if (exclusiveQueryState(queryName).test(text)) continue;

  failed = true;
  console.error(`FAIL: ${name} (${file})`);
}

const issuePage = readFileSync(resolve(root, 'src/pages/IssueKeyPage.tsx'), 'utf8');
for (const [name, needle] of [
  ['Issue page waits for both critical queries', 'if (serversQuery.isPending || settingsQuery.isPending)'],
  ['Issue page stops on server query error', 'if (serversQuery.isError)'],
  ['Issue page stops on settings query error', 'if (settingsQuery.isError)'],
]) {
  if (issuePage.includes(needle)) continue;

  failed = true;
  console.error(`FAIL: ${name} (src/pages/IssueKeyPage.tsx)`);
}

if (failed) process.exit(1);
console.log(`Accessibility primitive checks passed: ${checks.length + routeChecks.length + 3}.`);
