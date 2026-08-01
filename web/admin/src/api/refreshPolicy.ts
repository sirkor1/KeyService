/**
 * Classifies paths eligible for a single transparent session refresh.
 * Kept pure and exported so UI/integration tests can cover the allow-list directly.
 */
export function shouldAttemptRefresh(path: string): boolean {
  // Bootstrapping the panel is the one auth request that needs a refresh retry.
  if (path === '/auth/me') return true;

  // Refresh itself must never recurse; credentials-changing endpoints must not be replayed.
  return !path.startsWith('/auth/');
}
