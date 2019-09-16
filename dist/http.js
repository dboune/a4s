"use strict";
/**
 * Code for signing HTTP requests, either through headers (`Authorization`)
 * or through query parameters (presigned URLs), see [[signRequest]].
 *
 * This module calculates the canonical request, signs its digest using the
 * `core` module, and also builds the `Authorization` header (or the query
 * parameters).
 */
/** */
Object.defineProperty(exports, "__esModule", { value: true });
const url_1 = require("url");
const querystring_1 = require("querystring");
const crypto_1 = require("crypto");
const core_1 = require("./core");
const endpoint_1 = require("./util/endpoint");
const request_1 = require("./util/request");
function escape(str) {
    const digits = '0123456789ABCDEF';
    const at = (a, x, b) => (a <= x && x <= b);
    return Array.from(Buffer.from(str)).map(x => (at(0x61, x | 0x20, 0x7A) || at(0x30, x, 0x39) || x === 0x2D || x === 0x2E || x === 0x5F || x === 0x7E) ?
        String.fromCharCode(x) : `%${digits[x >> 4]}${digits[x & 0xF]}`).join('');
}
/**
 * Get canonical URL string (low-level)
 * @category Canonical request
 */
function getCanonicalURI(pathName, options) {
    let parts = pathName.split('/').map(querystring_1.unescape);
    if (!(options && options.dontNormalize)) {
        const newParts = [];
        let endingSlash = true;
        for (const part of parts) {
            endingSlash = true;
            if (part === '..') {
                newParts.pop();
            }
            else if (!(part === '' || part === '.')) {
                endingSlash = false;
                newParts.push(part);
            }
        }
        parts = [''].concat(newParts).concat(endingSlash ? [''] : []);
    }
    parts = parts.map(escape);
    if (!(options && options.onlyEncodeOnce)) {
        parts = parts.map(escape);
    }
    return parts.join('/');
}
exports.getCanonicalURI = getCanonicalURI;
/**
 * Get canonical query string (low-level)
 * @category Canonical request
 */
function getCanonicalQuery(query) {
    const pquery = query instanceof url_1.URLSearchParams ?
        query : new url_1.URLSearchParams(query);
    const parts = [];
    // .sort() uses UTF-16 code units instead of codepoints... close enough
    for (const key of Array.from(new Set(pquery.keys())).sort()) {
        if (!key) {
            continue; // FIXME: verify that services need empty keys stripped
        }
        const pkey = escape(key) + '=';
        for (const value of pquery.getAll(key).sort()) {
            parts.push(pkey + escape(value));
        }
    }
    return parts.join('&');
}
exports.getCanonicalQuery = getCanonicalQuery;
/**
 * Get canonical headers and signed header strings (low-level)
 * @param headers Headers object
 * @returns Array with [ canonicalHeaders, signedHeaders ]
 * @category Canonical request
 */
function getCanonicalHeaders(headers) {
    const trim = (x) => x.trim().replace(/\s+/g, ' ');
    const normalized = {};
    for (const key of Object.keys(headers)) {
        const name = key.toLowerCase();
        if ({}.hasOwnProperty.call(normalized, name)) {
            throw new Error(`Duplicate headers found: '${name}'`);
        }
        const value = headers[key];
        normalized[name] = value instanceof Array ?
            value.map(trim).join(',') : trim(value + '');
    }
    const signedHeaders = Object.keys(normalized).sort();
    const canonicalHeaders = signedHeaders.map(k => `${k}:${normalized[k]}\n`).join('');
    return [canonicalHeaders, signedHeaders.join(';')];
}
exports.getCanonicalHeaders = getCanonicalHeaders;
const EMPTY_HASH = crypto_1.createHash('sha256').digest('hex');
/**
 * Produce the body hash to include in canonical request (low-level)
 * @category Canonical request
 */
function hashBody(body, options) {
    if (!body) {
        return EMPTY_HASH;
    }
    return (typeof body.hash === 'string') ? body.hash
        : crypto_1.createHash('sha256').update(body).digest('hex');
}
exports.hashBody = hashBody;
/**
 * Function to generate a canonical request string.
 * Most users won't need to call this directly.
 *
 * @param method HTTP method
 * @param pathname URL pathname (i.e. without query string)
 * @param query Query parameters (if a string or object is provided, it will be parsed with `URLSearchParams`)
 * @param cheaders Result of [[getCanonicalHeaders]]
 * @param body Request body to calculate hash of (alternatively you may
 *             calculate it yourself and pass it as `{ hash: '<hex>' }`)
 * @param options Other options
 * @returns The canonical request string
 * @category Canonical request
 */
function getCanonical(method, pathname, query, cheaders, body, options) {
    const [canonicalHeaders, signedHeaders] = cheaders;
    return [
        method.toUpperCase().trim(),
        getCanonicalURI(pathname, options),
        getCanonicalQuery(query),
        canonicalHeaders,
        signedHeaders,
        hashBody(body, options),
    ].join('\n');
}
exports.getCanonical = getCanonical;
/**
 * Method to construct the value of the `Authorization`
 * header from its data.
 */
function buildAuthorization(data) {
    const fields = [
        `Credential=${data.credential}`,
        `SignedHeaders=${data.signedHeaders}`,
        `Signature=${data.signature.toString('hex')}`,
    ];
    return `${data.algorithm} ${fields.join(', ')}`;
}
exports.buildAuthorization = buildAuthorization;
/**
 * Method to parse an Authorization header. The Authorization
 * should follow the syntax of [[buildAuthorization]] and must
 * have at least Signature, SignedHeaders and Credential (in
 * any order). Note that no validation is done on any of the
 * returned values other than signature. If there are repeated
 * fields, the last one wins.
 * @returns Header values (see [[buildAuthorization]] argument)
 * @throws If there's a syntax error
 */
function parseAuthorization(header) {
    const split1 = (x, token) => {
        const idx = x.indexOf(token);
        if (idx === -1) {
            throw new Error('Invalid authorization header structure');
        }
        return [x.substring(0, idx), x.substring(idx + 1)];
    };
    const parts = split1(header.trimLeft(), ' ');
    const rawFields = parts[1].split(',').map(x => x.trim());
    const fields = new Map(rawFields.map(x => split1(x, '=')));
    if (!fields.has('Signature') || !fields.has('Credential') || !fields.has('SignedHeaders')) {
        throw new Error('Invalid authorization header (missing / extra fields)');
    }
    if (!/^([0-9a-f]{2})+$/.test(fields.get('Signature'))) {
        throw new Error('Invalid signature format');
    }
    return {
        algorithm: parts[0].trim(),
        credential: fields.get('Credential'),
        signedHeaders: fields.get('SignedHeaders'),
        signature: Buffer.from(fields.get('Signature'), 'hex'),
    };
}
exports.parseAuthorization = parseAuthorization;
/**
 * Signs an HTTP request using [[getCanonical]], calculating
 * its digest and signing it with [[signDigest]]. It then returns
 * the generated parameters for header / query authorization.
 *
 * The input parameters are never modified, regardless of the `set` option.
 *
 * The timestamp is taken from the `X-Amz-Date` header (or query parameter,
 * if query signing is requested). If not present, it's generated with
 * [[formatTimestamp]] and returned along with the other authorization
 * parameters.
 *
 * This is a low-level function, it doesn't perform any normalization
 * and assumes all required headers / parameters are there. Most
 * users will want [[signRequest]] instead.
 *
 * @param credentials Credentials to sign request with
 * @param method HTTP method
 * @param pathname URL pathname (i.e. without query string)
 * @param query Query parameters (if a string or object is provided, it will be parsed with `URLSearchParams`)
 * @param headers HTTP headers to include in the canonical request.
 * @param body Request body to calculate hash of (alternatively you may
 *             calculate it yourself and pass it as `{ hash: '<hex>' }`)
 * @param options Other options
 * @returns Authentication headers / query parameters
 * @category Signing
 */
function signRequestRaw(credentials, method, pathname, query, headers, body, options) {
    const isQuery = options && options.query;
    const result = {};
    const parameter = isQuery ?
        'X-Amz-Signature' : request_1.getHeader(headers, 'authorization')[0];
    // Extract / populate timestamp
    let timestamp = isQuery ?
        query.get('X-Amz-Date') : request_1.getHeader(headers, 'x-amz-date')[1];
    if (!timestamp) {
        const name = isQuery ? 'X-Amz-Date' : 'x-amz-date';
        timestamp = result[name] = core_1.formatTimestamp();
    }
    // Calculate body hash
    const hash = hashBody(body);
    if (!isQuery && options && options.setContentHash) {
        result[request_1.getHeader(headers, 'x-amz-content-sha256')[0]] = hash;
    }
    // Derive signing key
    const { signing, credential } = core_1.getSigning(timestamp, credentials, options);
    // Set other parameters if needed, delete final parameter
    if (!isQuery) {
        headers = { ...headers, ...result };
        delete headers[parameter];
    }
    const cheaders = getCanonicalHeaders(headers);
    if (isQuery) {
        result['X-Amz-Algorithm'] = core_1.MAIN_ALGORITHM;
        result['X-Amz-Credential'] = credential;
        result['X-Amz-SignedHeaders'] = cheaders[1];
        query = new url_1.URLSearchParams(query);
        Object.keys(result).forEach(k => query.set(k, result[k]));
        query.delete(parameter);
    }
    // Construct canonical request, digest, and sign
    const creq = getCanonical(method, pathname, query, cheaders, { hash }, options);
    const digest = crypto_1.createHash('sha256').update(creq).digest('hex');
    const signature = core_1.signDigest(core_1.MAIN_ALGORITHM, digest, timestamp, signing);
    // Add final parameter
    result[parameter] = isQuery ? signature.toString('hex') :
        buildAuthorization({ signature, credential,
            algorithm: core_1.MAIN_ALGORITHM, signedHeaders: cheaders[1] });
    return result;
}
exports.signRequestRaw = signRequestRaw;
/**
 * High-level function that signs an HTTP request using
 * `AWS-HMAC-SHA256` with either headers (`Authorization`) or query
 * parameters (presigned URL) depending on the `query` option.
 *
 * It populates some parameters (see below), calls [[signRequestRaw]] and
 * (if `set` is enabled) adds the parameters to `headers` or `searchParams`.
 *
 *  - If `serviceName` or `regionName` are not present, they are detected
 *    from `url.host`. If `url.host` is not present, it is populated from
 *    `serviceName` / `regionName` (independently of the `set` option).
 *
 *  - If the `Host` header is not present, this method behaves as if
 *    it was set to `url.host`.
 *
 *  - The timestamp is taken from the `X-Amz-Date` header (or query parameter,
 *    if query signing is requested). If not present, it's generated with
 *    [[formatTimestamp]] and returned/set along with the other authorization
 *    parameters.
 *
 * Keep in mind headers are matched case insensitively,
 * but query parameters aren't.
 *
 * For query signing: If `set` is enabled and `url` is a string, it will
 * be replaced with a new string; otherwise `url.searchParams` will be mutated.
 *
 * @param credentials Credentials to sign the request with
 * @param request HTTP request to sign, see [[SignedRequest]]
 * @param options Other options
 * @returns Authorization headers / query parameters
 * @category Signing
 */
function signRequest(credentials, request, options) {
    let { url, headers, method, body } = request;
    url = typeof url === 'string' ? new url_1.URL(url) : url;
    // Detect url.host or serviceName / regionName
    if (!url.host) {
        if (!credentials.serviceName) {
            throw new Error('Neither url.host nor serviceName was provided');
        }
        url.host = endpoint_1.formatHost(credentials.serviceName, credentials.regionName);
        credentials = { regionName: endpoint_1.DEFAULT_REGION, ...credentials };
    }
    else if (!credentials.serviceName || !credentials.regionName) {
        credentials = { ...endpoint_1.parseHost(url.host), ...credentials };
    }
    // Populate host header if necessary
    if (!request_1.getHeader(headers, 'host')[1]) {
        headers = { ...headers, host: url.host };
    }
    // Sign the request
    const query = url.searchParams || new url_1.URLSearchParams();
    const result = signRequestRaw(credentials, method || 'GET', url.pathname || '/', query, headers || {}, body, options);
    // Set the parameters if required
    if (options && options.set) {
        if (options && options.query) {
            if (!url.searchParams) {
                url.searchParams = query;
            }
            Object.keys(result).forEach(k => query.set(k, result[k]));
            if (typeof request.url === 'string') {
                request.url = url.toString();
            }
        }
        else {
            const rh = request.headers = request.headers || {};
            Object.keys(result).forEach(k => { rh[k] = result[k]; });
        }
    }
    return result;
}
exports.signRequest = signRequest;
//# sourceMappingURL=http.js.map