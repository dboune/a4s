"use strict";
/**
 * Utilities to normalize and work with requests and headers.
 */
/** */
Object.defineProperty(exports, "__esModule", { value: true });
const url_1 = require("url");
const normalizeValue = (value) => value instanceof Array ? value.join(',') : value + '';
/**
 * Find the name and value of a header in an unnormalized headers object.
 *
 * @param headers Headers object
 * @param name Name of header to find
 * @returns Array with name and value (as string); if not found
 * then [name.toLowerCase(), undefined] will be returned.
 */
function getHeader(headers, name) {
    name = name.toLowerCase();
    if (headers) {
        for (const key of Object.keys(headers)) {
            if (key.toLowerCase() === name) {
                return [key, normalizeValue(headers[key])];
            }
        }
    }
    return [name, undefined];
}
exports.getHeader = getHeader;
/**
 * Generate HTTP request options from a [[SignedRequest]] object.
 */
function toRequestOptions(request) {
    let { method, url, headers } = request;
    url = typeof url === 'string' ? new url_1.URL(url) : url;
    const { host, pathname, searchParams } = url;
    const query = searchParams && searchParams.toString();
    const path = (pathname || '/') + (query ? '?' + query : '');
    return { method, headers, host, path };
}
exports.toRequestOptions = toRequestOptions;
/**
 * Gemerate a URL string from the `url` field of a [[SignedRequest]].
 */
function toURL(url) {
    if (typeof url === 'string') {
        return url;
    }
    if (url instanceof url_1.URL) {
        return url.toString();
    }
    if (url.pathname && url.pathname[0] !== '/') {
        throw new Error("Pathname without leading slash can't be converted to URL");
    }
    const origin = url.host ? `https://${url.host}` : '';
    const query = url.searchParams && url.searchParams.toString();
    const pathname = url.pathname ? encodeURI(url.pathname) : '/';
    return origin + pathname + (query ? `?${query}` : '');
}
exports.toURL = toURL;
//# sourceMappingURL=request.js.map