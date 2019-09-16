"use strict";
/**
 * This module implements S3 Chunked Upload signing, which is a
 * special form of the usual `Authorization` signing for S3 requests
 * which signs the payload progressively, without requiring you to
 * calculate its digest first. See [[signS3ChunkedRequest]] and
 * [[createS3PayloadSigner]].
 */
/** */
Object.defineProperty(exports, "__esModule", { value: true });
const crypto_1 = require("crypto");
const stream_1 = require("stream");
const core_1 = require("./core");
const http_1 = require("./http");
const s3_1 = require("./s3");
const request_1 = require("./util/request");
/** Special value for payload digest, which indicates payload streaming encoding */
exports.PAYLOAD_STREAMING = 'STREAMING-AWS4-HMAC-SHA256-PAYLOAD';
/** Minimum length for chunks in payload streaming, 8KB */
exports.CHUNK_MIN = 8 * 1024;
/** Algorithm used for chunk signatures in payload streaming */
exports.ALGORITHM_STREAMING = 'AWS4-HMAC-SHA256-PAYLOAD';
// AWS docs don't mention it anywhere, but format needs to be exactly this:
// '[LENGTH];chunk-signature=[SIGNATURE]\r\n[BYTES]\r\n'
const CRLF = '\r\n';
const EMPTY_HASH = crypto_1.createHash('sha256').digest('hex');
function calculateChunks(bodyLength, chunkLength) {
    if (Math.floor(chunkLength) !== chunkLength || chunkLength < exports.CHUNK_MIN) {
        throw new Error('Invalid chunk length');
    }
    if (Math.floor(bodyLength) !== bodyLength || bodyLength < 0) {
        throw new Error('Invalid body length');
    }
    const chunks = Math.floor(bodyLength / chunkLength);
    return { chunks, lastLength: bodyLength - chunks * chunkLength };
}
function patchHeaders(request, extra, set) {
    const headers = set ?
        (request.headers = request.headers || {}) : { ...request.headers };
    Object.keys(extra).forEach(k => { headers[k] = extra[k]; });
    return headers;
}
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
function signS3Chunk(lastSignature, signing, timestamp, chunk) {
    const digest = [lastSignature, EMPTY_HASH, http_1.hashBody(chunk)].join('\n');
    return core_1.signDigest(exports.ALGORITHM_STREAMING, digest, timestamp, signing).toString('hex');
}
exports.signS3Chunk = signS3Chunk;
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
function signS3ChunkedRequest(credentials, request, bodyLength, chunkLength, options) {
    const originalRequest = request;
    let { headers } = request;
    const extra = {};
    // Calculate total length (body + metadata)
    const { chunks, lastLength } = calculateChunks(bodyLength, chunkLength);
    const chunkHeader = `${chunkLength.toString(16)};chunk-signature=`;
    const lastHeader = `${lastLength.toString(16)};chunk-signature=`;
    const finalHeader = '0;chunk-signature=';
    const totalLength = bodyLength + (chunkHeader.length + 64 + 4) * chunks
        + (lastLength ? lastHeader.length + 64 + 4 : 0) + finalHeader.length + 64 + 4;
    // Set headers
    const [encodingName, encoding] = request_1.getHeader(headers, 'content-encoding');
    if (!(encoding && /^\s*aws-chunked\s*($|,)/i.test(encoding))) {
        extra[encodingName] = 'aws-chunked' + (encoding ? `,${encoding}` : '');
    }
    let timestamp = request_1.getHeader(headers, 'x-amz-date')[1];
    if (!timestamp) {
        timestamp = extra['x-amz-date'] = core_1.formatTimestamp();
    }
    extra['content-length'] = totalLength;
    extra['x-amz-decoded-content-length'] = bodyLength;
    // Sign the request
    headers = patchHeaders(request, extra, options && options.set);
    request = { ...request, headers, body: { hash: exports.PAYLOAD_STREAMING } };
    const parameters = { ...extra, ...s3_1.signS3Request(credentials, request, { ...options, query: false }) };
    originalRequest.url = request.url;
    // Derive key used by signRequest
    const auth = http_1.parseAuthorization(parameters.authorization);
    const [regionName, serviceName] = auth.credential.split('/').slice(2, 4);
    const derive = (options && options.getSigningData) || core_1.getSigningData;
    const signing = derive(timestamp, credentials.secretKey, regionName, serviceName);
    // Chunk signer implementation
    let signature = auth.signature.toString('hex');
    let dataCount = 0;
    let done = false;
    const signer = function chunkSigner(chunk) {
        if (done) {
            throw new Error('Payload is complete, no more calls are needed');
        }
        let length = chunkLength, header = chunkHeader;
        if (bodyLength - dataCount < chunkLength) {
            [length, header] = (dataCount !== bodyLength) ?
                [lastLength, lastHeader] : [0, finalHeader];
        }
        if ((chunk ? chunk.length : 0) !== length) {
            throw new Error(`Unexpected chunk size (got ${chunk && chunk.length}, expected ${length})`);
        }
        signature = signS3Chunk(signature, signing, timestamp, chunk);
        dataCount += length;
        done = !length;
        return (dataCount === length ? '' : CRLF) +
            header + signature + CRLF + (length ? '' : CRLF);
    };
    return { parameters, signer };
}
exports.signS3ChunkedRequest = signS3ChunkedRequest;
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
function createS3PayloadSigner(credentials, request, bodyLength, chunkLength, options) {
    const { parameters, signer } = signS3ChunkedRequest(credentials, request, bodyLength, chunkLength, options);
    let pending = [], length = 0, hash = crypto_1.createHash('sha256');
    const pushData = (data) => {
        pending.push(data);
        hash.update(data);
        length += data.length;
    };
    const flushData = (stream) => {
        stream.push(signer({ hash: hash.digest('hex'), length }));
        pending.forEach(data => stream.push(data));
        pending = [], length = 0, hash = crypto_1.createHash('sha256');
    };
    const stream = new stream_1.Transform({
        transform(data, _, callback) {
            while (length + data.length >= chunkLength) {
                const l = (chunkLength - length);
                pushData(data.slice(0, l)); // mutates length!
                flushData(this);
                data = data.slice(l);
            }
            data.length && pushData(data);
            callback();
        },
        final(callback) {
            length && flushData(this);
            this.push(signer());
            callback();
        },
    });
    return { parameters, signer: stream };
}
exports.createS3PayloadSigner = createS3PayloadSigner;
//# sourceMappingURL=s3_chunked.js.map