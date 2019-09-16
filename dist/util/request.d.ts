/**
 * Utilities to normalize and work with requests and headers.
 */
/** */
/// <reference types="node" />
import { SignedRequest } from '../http';
import { RequestOptions } from 'http';
/**
 * Find the name and value of a header in an unnormalized headers object.
 *
 * @param headers Headers object
 * @param name Name of header to find
 * @returns Array with name and value (as string); if not found
 * then [name.toLowerCase(), undefined] will be returned.
 */
export declare function getHeader(headers: {
    [key: string]: string | string[] | number | undefined;
} | undefined, name: string): [string, string | undefined];
/**
 * Generate HTTP request options from a [[SignedRequest]] object.
 */
export declare function toRequestOptions(request: SignedRequest): RequestOptions;
/**
 * Gemerate a URL string from the `url` field of a [[SignedRequest]].
 */
export declare function toURL(url: SignedRequest["url"]): string;
