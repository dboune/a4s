/**
 * Code for signing generic messages using AWS Signature version 4.
 *
 * This module contains only common signing logic (i.e. not HTTP specific);
 * main functions are [[formatTimestamp]] to generate timestamps, [[getSigning]]
 * to derive the signing key, and [[signDigest]] to sign a hash.
 */
/** */
/// <reference types="node" />
export interface SignOptions {
    /** Specify an alternate implementation of [[getSigningData]], i.e. a cached one */
    getSigningData?: GetSigningData;
}
export interface SigningData {
    key: Buffer;
    scope: string;
}
export declare type GetSigningData = (dateStamp: string, secretKey: string, regionName: string, serviceName: string) => SigningData;
export interface RelaxedCredentials {
    accessKey: string;
    secretKey: string;
    regionName?: string;
    serviceName?: string;
}
export interface Credentials extends RelaxedCredentials {
    regionName: string;
    serviceName: string;
}
/** Format the date stamp for [[getSigningData]] (low-level). */
export declare function formatDate(date?: Date): string;
/**
 * Derive the signature key and credential scope (low-level)
 *
 * `dateStamp` can be created with [[formatDate]]. Because it's cropped
 * to 8 characters, a full timestamp (see [[formatTimestamp]]) also works.
 *
 * @returns Signing data (key and credentials scope)
 * @category Key derivation
 */
export declare function getSigningData(dateStamp: string, secretKey: string, regionName: string, serviceName: string): SigningData;
export declare namespace getSigningData {
    var makeSimpleCache: () => GetSigningData;
}
/** Format the timestamp for a request (low-level) */
export declare function formatTimestamp(date?: Date): string;
/**
 * Sign an arbitrary string using the derived key (low-level)
 *
 * @param sts String to sign
 * @param key The signing key obtained from [[getSigningData]]
 * @returns The binary signature
 * @category Signing
 */
export declare const signString: (key: Buffer, sts: string | Buffer) => Buffer;
/** Main algorithm ID */
export declare const MAIN_ALGORITHM = "AWS4-HMAC-SHA256";
/**
 * Construct and sign a standard payload digest string (low-level)
 *
 * @param algorithm Algorithm used for calculating `payloadDigest`, i.e. `AWS4-HMAC-SHA256`
 * @param payloadDigest The payload digest (typically hex-encoded)
 * @param timestamp Timestamp used in the request
 * @param signing The signing data obtained from [[getSigningData]] pr [[getSigning]] (its date should match `timestamp`)
 * @returns The binary signature
 * @category Signing
 */
export declare const signDigest: (algorithm: string, payloadDigest: string, timestamp: string, signing: SigningData) => Buffer;
/**
 * Convenience version of [[getSigningData]] that accepts a
 * `Credentials` object, and also returns a credential string.
 *
 * @param dateStamp The timestamp / date stamp
 * @param credentials Credentials to derive from
 * @returns Signing data and credential string
 * @category Key derivation
 */
export declare function getSigning(dateStamp: string, credentials: Credentials, options?: SignOptions): {
    signing: SigningData;
    credential: string;
};
/**
 * High-level function that uses [[getSigning]] to derive the
 * signing key, and then [[signDigest]] to calculate the signature.
 *
 * @param credentials Info to derive key and credentials scope
 * @param algorithm Algorithm used for calculating `payloadDigest`, i.e. `AWS4-HMAC-SHA256`
 * @param payloadDigest The payload digest
 * @param timestamp Timestamp used in the request
 * @returns The signature and credential string
 * @category Signing
 */
export declare function sign(credentials: Credentials, algorithm: string, payloadDigest: string, timestamp: string, options?: SignOptions): {
    signature: Buffer;
    credential: string;
};
