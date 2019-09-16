/**
 * Code for signing HTTP requests, either through headers (`Authorization`)
 * or through query parameters (presigned URLs), see [[signRequest]].
 *
 * This module calculates the canonical request, signs its digest using the
 * `core` module, and also builds the `Authorization` header (or the query
 * parameters).
 */
/** */
/// <reference types="node" />
import { URLSearchParams } from 'url';
import { OutgoingHttpHeaders } from 'http';
import { RelaxedCredentials, Credentials, SignOptions } from './core';
export interface CanonicalOptions {
    /** Disable path normalization (i.e. `.`, `..`, consecutive slashes) */
    dontNormalize?: boolean;
    /** Don't percent-encode path segments twice */
    onlyEncodeOnce?: boolean;
}
export interface SignHTTPOptions {
    /**
     * Add the returned parameters to the passed headers (or searchParams,
     * if query signing was requested)
     */
    set?: boolean;
    /**
     * Return query authorization parameters instead of headers (the default)
     */
    query?: boolean;
    /**
     * For header authorization, set the `x-amz-content-sha256` header
     */
    setContentHash?: boolean;
}
export interface SignedRequest {
    /** HTTP method (default: GET) */
    method?: string;
    /** Resource URL (if it's a string, it'll be parsed using `new URL()`) */
    url: string | {
        /** Host part of the URL, including port number */
        host?: string;
        /** Pathname part of the URL (default: /) */
        pathname?: string;
        /** Query parameters (default: empty) */
        searchParams?: URLSearchParams;
    };
    /** HTTP headers */
    headers?: OutgoingHttpHeaders;
    /** Request body to calculate hash of (alternatively you may
     * calculate it yourself and pass it as `{ hash: '<hex>' }`) */
    body?: Buffer | string | {
        hash: string;
    };
}
/**
 * Get canonical URL string (low-level)
 * @category Canonical request
 */
export declare function getCanonicalURI(pathName: string, options?: CanonicalOptions): string;
/**
 * Get canonical query string (low-level)
 * @category Canonical request
 */
export declare function getCanonicalQuery(query: URLSearchParams | string | {
    [key: string]: string;
}): string;
/**
 * Get canonical headers and signed header strings (low-level)
 * @param headers Headers object
 * @returns Array with [ canonicalHeaders, signedHeaders ]
 * @category Canonical request
 */
export declare function getCanonicalHeaders(headers: OutgoingHttpHeaders): [string, string];
/**
 * Produce the body hash to include in canonical request (low-level)
 * @category Canonical request
 */
export declare function hashBody(body: SignedRequest["body"], options?: CanonicalOptions): string;
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
export declare function getCanonical(method: string, pathname: string, query: URLSearchParams | string | {
    [key: string]: string;
}, cheaders: [string, string], body: SignedRequest["body"], options?: CanonicalOptions): string;
/**
 * Method to construct the value of the `Authorization`
 * header from its data.
 */
export declare function buildAuthorization(data: {
    algorithm: string;
    signature: Buffer;
    credential: string;
    signedHeaders: string;
}): string;
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
export declare function parseAuthorization(header: string): {
    algorithm: string;
    credential: string;
    signedHeaders: string;
    signature: Buffer;
};
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
export declare function signRequestRaw(credentials: Credentials, method: string, pathname: string, query: URLSearchParams, headers: OutgoingHttpHeaders, body: SignedRequest["body"], options?: SignHTTPOptions & CanonicalOptions & SignOptions): {
    [key: string]: string;
};
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
export declare function signRequest(credentials: RelaxedCredentials, request: SignedRequest, options?: SignHTTPOptions & CanonicalOptions & SignOptions): {
    [key: string]: string;
};
