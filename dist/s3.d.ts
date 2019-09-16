/**
 * This module contains signing logic that is specific for the S3
 * service, see [[signS3Request]].
 *
 * Additionally there's POST form parameter authentication,
 * which is designed mainly to allow users to upload files
 * to S3 directly from their browser. See [[signS3Policy]].
 */
/** */
import { RelaxedCredentials, GetSigningData, SignOptions } from './core';
import { SignHTTPOptions, CanonicalOptions, SignedRequest } from './http';
export interface PolicySignOptions {
    timestamp?: string | Date;
    getSigningData?: GetSigningData;
}
export interface SignedS3Request extends SignedRequest {
    /** If set to true, the hash will be set to true */
    unsigned?: boolean;
}
/** Maximum value for the X-Amz-Expires query parameter */
export declare const EXPIRES_MAX = 604800;
/** Option defaults for the S3 service */
export declare const S3_OPTIONS: {
    dontNormalize: boolean;
    onlyEncodeOnce: boolean;
    setContentHash: boolean;
};
/** Special value for payload digest, which indicates the payload is not signed */
export declare const PAYLOAD_UNSIGNED = "UNSIGNED-PAYLOAD";
/**
 * High-level function that signs an HTTP request for S3 using
 * `AWS-HMAC-SHA256` with either headers (`Authorization`) or query
 * parameters (presigned URL) depending on the `query` option.
 *
 * This is a special version of [[signRequest]] that implements
 * some quirks needed for S3:
 *
 *  - You can set `unsigned` in the request to leave payload unsigned
 *    (body hash is set to `UNSIGNED_PAYLOAD`). For query authorization
 *    it's on by default (S3 query authorization can't sign the body).
 *
 *  - For query authorization, the `X-Amz-Expires` parameter is
 *    set to `EXPIRES_MAX` if not present.
 *
 *  - `S3_OPTIONS` are applied by default (disables normalization
 *    and double encoding when calculating signature, adds
 *    `x-amz-content-sha256` for header authorization). Also,
 *    `serviceName` defaults to `s3` if host was not passed.
 *
 * The extra parameters are returned with the others, and also
 * set if requested.
 *
 * @param credentials Credentials to sign the request with
 * @param request HTTP request to sign, see [[SignedS3Request]]
 * @param options Other options
 * @returns Authorization headers / query parameters
 */
export declare function signS3Request(credentials: RelaxedCredentials, request: SignedS3Request, options?: SignHTTPOptions & CanonicalOptions & SignOptions): {
    [key: string]: string;
};
/**
 * (POST form param based authentication)
 *
 * This method signs the passed policy and returns the
 * [authentication parameters][policy-auth] that you need to attach
 * to the [created form][create-form].
 *
 * See [this][construct-policy] for how to write the policy.
 * The policy shouldn't contain any authentication parameters (such
 * as `x-amz-date`); these will be added before signing it.
 *
 * > For a working example of use, see `demo_s3_post`.
 *
 * [create-form]: https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-HTTPPOSTForms.html
 * [construct-policy]: https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-HTTPPOSTConstructPolicy.html
 * [policy-auth]: https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-authentication-HTTPPOST.html
 *
 * @param credentials The IAM credentials to use for signing
 *                   (service name defaults to 's3', and the default region)
 * @param policy The policy object
 * @param timestamp You can optionally provide the timestamp for signing,
 *                  otherwise it will be generated using [[formatTimestamp]]
 * @returns Key - value object containing the form parameters
 */
export declare function signS3Policy(credentials: RelaxedCredentials, policy: any, options?: PolicySignOptions): {
    [key: string]: string;
};
import * as chunked from './s3_chunked';
export { chunked };
