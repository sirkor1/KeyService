import { shouldAttemptRefresh } from './refreshPolicy';

/**
 * HTTP-клиент панели.
 *
 * Токен живёт в httpOnly-куке, поэтому JS его не видит и не выставляет
 * заголовок Authorization — достаточно credentials: 'include'.
 * Заголовок X-Requested-With обязателен на мутациях: вместе с SameSite=Strict
 * он закрывает CSRF.
 */

/** Ошибка API. Несёт HTTP-статус и машинный код из ProblemDetails. */
export class ApiError extends Error {
  readonly status: number;
  readonly code: string | undefined;

  constructor(status: number, message: string, code?: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
  }

  /** Не аутентифицирован — панель должна отправить на экран входа. */
  get isUnauthorized(): boolean {
    return this.status === 401;
  }

  /** Аутентифицирован, но роль не позволяет. */
  get isForbidden(): boolean {
    return this.status === 403;
  }
}

interface ProblemDetails {
  title?: string;
  detail?: string;
  status?: number;
  code?: string;
  error?: string;
}

type Query = Record<string, string | number | boolean | null | undefined>;

// One refresh for all simultaneous 401s (dashboard fan-out after an expired access cookie).
let refreshInFlight: Promise<boolean> | null = null;

async function refreshPanelSession(): Promise<boolean> {
  if (!refreshInFlight) {
    refreshInFlight = fetch('/api/auth/refresh', {
      method: 'POST',
      headers: { 'X-Requested-With': 'panel' },
      credentials: 'include',
    })
      .then((response) => response.status === 204)
      .catch(() => false)
      .finally(() => {
        refreshInFlight = null;
      });
  }
  return refreshInFlight;
}

function buildUrl(path: string, query?: Query): string {
  const url = `/api${path}`;
  if (!query) return url;

  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    // Пустая строка — это «фильтр не задан», а не «искать пустоту».
    if (value === null || value === undefined || value === '') continue;
    params.append(key, String(value));
  }

  const qs = params.toString();
  return qs ? `${url}?${qs}` : url;
}

async function toApiError(response: Response): Promise<ApiError> {
  let problem: ProblemDetails = {};
  try {
    problem = (await response.json()) as ProblemDetails;
  } catch {
    // Тело может быть пустым или не-JSON — тогда обходимся статусом.
  }

  const message =
    problem.title ?? problem.detail ?? problem.error ?? defaultMessage(response.status);

  return new ApiError(response.status, message, problem.code);
}

function defaultMessage(status: number): string {
  switch (status) {
    case 401:
      return 'Требуется вход в панель.';
    case 403:
      return 'Недостаточно прав для этого действия.';
    case 404:
      return 'Не найдено.';
    case 429:
      return 'Слишком много запросов. Попробуйте через минуту.';
    case 502:
      return 'Сервер недоступен.';
    default:
      return 'Не удалось выполнить запрос.';
  }
}

async function request<T>(
  method: string,
  path: string,
  options: { query?: Query; body?: unknown; signal?: AbortSignal; retried?: boolean } = {},
): Promise<T> {
  const headers: Record<string, string> = { 'X-Requested-With': 'panel' };
  if (options.body !== undefined) headers['Content-Type'] = 'application/json';

  const response = await fetch(buildUrl(path, options.query), {
    method,
    headers,
    credentials: 'include',
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
    ...(options.signal ? { signal: options.signal } : {}),
  });

  if (response.status === 401 && !options.retried && shouldAttemptRefresh(path)) {
    if (await refreshPanelSession())
      return request<T>(method, path, { ...options, retried: true });
  }
  if (!response.ok) throw await toApiError(response);

  // 204 и пустое тело — законный ответ на мутацию.
  if (response.status === 204) return undefined as T;
  const text = await response.text();
  return (text ? JSON.parse(text) : undefined) as T;
}

export const api = {
  get: <T>(path: string, query?: Query, signal?: AbortSignal) =>
    request<T>('GET', path, { ...(query ? { query } : {}), ...(signal ? { signal } : {}) }),

  post: <T>(path: string, body?: unknown, query?: Query) =>
    request<T>('POST', path, {
      ...(body !== undefined ? { body } : {}),
      ...(query ? { query } : {}),
    }),

  put: <T>(path: string, body?: unknown) =>
    request<T>('PUT', path, body !== undefined ? { body } : {}),

  delete: <T>(path: string) => request<T>('DELETE', path),
};
