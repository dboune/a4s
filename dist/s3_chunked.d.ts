/**
 * This module implements S3 Chunked Upload signing, which is a
 * special form of the usual `Authorization` signing for S3 requests
 * which signs the payload progressively, without requiring you to
 * calculate its digest first. See [[signS3ChunkedRequest]] and
 * [[createS3PayloadSigner]].
 */
/** */
/// <reference types="node" />
import { Transform } from 'stream';
import { RelaxedCredentials, SignOptions, SigningData } from './core';
import { SignHTTPOptions, CanonicalOptions } from './http';
import { SignedS3Request } from './s3';
/** Special value for payload digest, which indicates payload streaming encoding */
export declare const PAYLOAD_STREAMING = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD";
/** Minimum length for chunks in payload streaming, 8KB */
export declare const CHUNK_MIN: number;
/** Algorithm used for chunk signatures in payload streaming */
export declare const ALGORITHM_STREAMING = "AWS4-HMAC-SHA256-PAYLOAD";
export interface ChunkDescription {
    hash: string;
    length: number;
}
export declare type ChunkSigner = (chunk?: Buffer | ChunkDescription) => string;
/**
 * Low-level function that calculates the signature for a chunk of
 * data. Most users should use [[createS3PayloadSigner]] or
 * [[signS3ChunkedRequest]].
 *
 * @param lastSignature Signature from previous chunk (or HTTP
 * request if this is the first chunk)
 * @param signing Signing data
 * @param timestamp Timestamp used for signing
 * @param chunk Chunk to calculate hash of (alternatively you may
 *              calculate it yourself and pass it as `{ hash: '<hex>' }`)
 * @returns Signature for the chunk
 */
export declare function signS3Chunk(lastSignature: string, signing: SigningData, timestamp: string, chunk?: Buffer | {
    hash: string;
}): string;
/**
 * Special version of [[signS3Request]] implementing 'payload
 * streaming', which allows you to send a signed payload in chunks,
 * without having to calculate its digest first.
 *
 * In addition to returning the authorization parameters, this function
 * returns a **chunk signer**. It's a function that should be called
 * with each chunk you want to send, and returns a header string that
 * must be prepended to it. When you have sent all the chunks, you
 * must call it again with no data to generate the trailing string.
 *
 * **Note:** All chunks must be of the passed `chunkLength`, except the
 * final one which can be smaller. An error will be thrown if you don't
 * adhere to this, or if the passed data doesn't match `bodyLength`. All
 * calls must pass data except for the final one.
 *
 * > For a working example of use, see [[createS3PayloadSigner]] and
 * > `demo_s3_upload`.
 *
 * @param credentials Credentials to sign the request with
 * @param request HTTP request to sign, see [[SignedS3Request]]
 * @param bodyLength Length of the payload you want to send
 * @param chunkLength Length of each data chunk (must be at least CHUNK_MIN)
 * @param options Other options (`query` is ignored)
 * @returns Object containing authorization parameters,
 * and the chunk signer function.
 */
export declare function signS3ChunkedRequest(credentials: RelaxedCredentials, request: SignedS3Request, bodyLength: number, chunkLength: number, options?: SignHTTPOptions & CanonicalOptions & SignOptions): {
    parameters: {
        [key: string]: string | number;
    };
    signer: ChunkSigner;
};
/**
 * Like [[signS3ChunkedRequest]] but instead of returning the chunk
 * signer function, this returns a `Transform` stream that does the
 * signing for you.
 *
 * Keep in mind an error will be thrown if the length of the
 * input data doesn't match the `bodyLength` you passed.
 *
 * > For a working example of use, see `demo_s3_upload`.
 *
 * @param credentials Credentials to sign the request with
 * @param request HTTP request to sign, see [[SignedS3Request]]
 * @param bodyLength Length of the payload you want to send
 * @param chunkLength Length of each data chunk (must be at least CHUNK_MIN)
 * @param options Other options (`query` is ignored)
 * @returns Object containing authorization parameters,
 * and the signing transform stream.
 */
export declare function createS3PayloadSigner(credentials: RelaxedCredentials, request: SignedS3Request, bodyLength: number, chunkLength: number, options?: SignHTTPOptions & CanonicalOptions & SignOptions): {
    parameters: {
        [key: string]: string | number;
    };
    signer: Transform;
};
