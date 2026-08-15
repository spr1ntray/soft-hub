const { Readable } = require('node:stream');

function abortError() {
  const error = new Error('Запрос отменён.');
  error.name = 'AbortError';
  return error;
}

function headerValue(headers, expectedName) {
  const wanted = String(expectedName || '').toLowerCase();
  if (!headers || typeof headers !== 'object' || !wanted) return null;
  for (const [name, rawValue] of Object.entries(headers)) {
    if (String(name).toLowerCase() !== wanted) continue;
    if (Array.isArray(rawValue)) return rawValue.map(String).join(', ');
    return rawValue === undefined || rawValue === null ? null : String(rawValue);
  }
  return null;
}

function responseHeaders(headers, overrides = {}) {
  const normalizedOverrides = new Map(
    Object.entries(overrides).map(([name, value]) => [String(name).toLowerCase(), String(value)]),
  );
  return Object.freeze({
    get(name) {
      const key = String(name || '').toLowerCase();
      return normalizedOverrides.has(key) ? normalizedOverrides.get(key) : headerValue(headers, key);
    },
  });
}

function createElectronManualFetch(requestFactory) {
  if (typeof requestFactory !== 'function') throw new TypeError('requestFactory must be a function');

  return async function electronManualFetch(input, init = {}) {
    const parsed = new URL(String(input));
    if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.hash) {
      throw new TypeError('Only credential-free HTTPS URLs are supported');
    }
    const method = String(init.method || 'GET').toUpperCase();
    if (method !== 'GET') throw new TypeError('Only GET requests are supported');
    const signal = init.signal;
    if (signal?.aborted) throw abortError();

    return await new Promise((resolve, reject) => {
      let request;
      let completed = false;
      let responseStarted = false;

      const cleanupSignal = () => signal?.removeEventListener('abort', onAbort);
      const rejectOnce = (error) => {
        if (completed) return;
        completed = true;
        cleanupSignal();
        reject(error);
      };
      const onAbort = () => {
        try { request?.abort(); } catch { /* Best effort. */ }
        if (!responseStarted) rejectOnce(abortError());
      };

      try {
        request = requestFactory({
          method,
          url: parsed.href,
          headers: init.headers || {},
          redirect: 'manual',
          credentials: 'omit',
          useSessionCookies: false,
        });
      } catch (error) {
        rejectOnce(error);
        return;
      }

      signal?.addEventListener('abort', onAbort, { once: true });
      request.once('redirect', (statusCode, _method, redirectUrl, headers) => {
        if (completed) return;
        const location = String(redirectUrl || headerValue(headers, 'location') || '');
        completed = true;
        cleanupSignal();
        resolve(Object.freeze({
          ok: false,
          status: Number(statusCode),
          url: parsed.href,
          headers: responseHeaders(headers, { location }),
          body: null,
        }));
        // Do not call followRedirect(). Electron will cancel this transaction;
        // fetchRedirectSafe validates the target and creates a fresh request.
      });
      request.once('response', (incoming) => {
        if (completed) {
          incoming.resume?.();
          return;
        }
        completed = true;
        responseStarted = true;
        const cleanupResponse = () => cleanupSignal();
        incoming.once('end', cleanupResponse);
        incoming.once('close', cleanupResponse);
        incoming.once('error', cleanupResponse);
        resolve(Object.freeze({
          ok: Number(incoming.statusCode) >= 200 && Number(incoming.statusCode) < 300,
          status: Number(incoming.statusCode),
          url: parsed.href,
          headers: responseHeaders(incoming.headers),
          body: Readable.toWeb(incoming),
        }));
      });
      request.once('error', (error) => rejectOnce(error));
      request.once('abort', () => rejectOnce(abortError()));
      try {
        request.end();
      } catch (error) {
        rejectOnce(error);
      }
    });
  };
}

module.exports = {
  createElectronManualFetch,
  headerValue,
  responseHeaders,
};
