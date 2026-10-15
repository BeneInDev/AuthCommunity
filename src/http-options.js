const HTTP_TIMEOUT_MS = 10000;

function externalRequestOptions(timeoutMs = HTTP_TIMEOUT_MS) {
    return { timeout: timeoutMs, signal: AbortSignal.timeout(timeoutMs), maxRedirects: 0 };
}

module.exports = { HTTP_TIMEOUT_MS, externalRequestOptions };
