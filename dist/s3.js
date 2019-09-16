"use strict";
/**
 * This module contains signing logic that is specific for the S3
 * service, see [[signS3Request]].
 *
 * Additionally there's POST form parameter authentication,
 * which is designed mainly to allow users to upload files
 * to S3 directly from their browser. See [[signS3Policy]].
 */
/** */
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result["default"] = mod;
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
const url_1 = require("url");
const core_1 = require("./core");
const http_1 = require("./http");
const endpoint_1 = require("./util/endpoint");
/** Maximum value for the X-Amz-Expires query parameter */
exports.EXPIRES_MAX = 604800;
/** Option defaults for the S3 service */
exports.S3_OPTIONS = {
    dontNormalize: true,
    onlyEncodeOnce: true,
    setContentHash: true,
};
/** Special value for payload digest, which indicates the payload is not signed */
exports.PAYLOAD_UNSIGNED = 'UNSIGNED-PAYLOAD';
function patchURL(request, extra, url, set) {
    if (set || request.url !== url) {
        if (!url.searchParams) {
            url.searchParams = new url_1.URLSearchParams();
        }
    }
    else {
        const { host, pathname, searchParams } = url;
        url = { host, pathname, searchParams: new url_1.URLSearchParams(searchParams) };
    }
    Object.keys(extra).forEach(k => url.searchParams.set(k, extra[k]));
    return url;
}
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
function signS3Request(credentials, request, options) {
    const isQuery = options && options.query;
    let { url, body, unsigned } = { unsigned: isQuery, ...request };
    url = typeof url === 'string' ? new url_1.URL(url) : url;
    const originalRequest = request;
    const extra = {};
    if (isQuery) {
        if (!(url.searchParams && url.searchParams.has('X-Amz-Expires'))) {
            extra['X-Amz-Expires'] = exports.EXPIRES_MAX.toString();
            url = patchURL(request, extra, url, options && options.set);
        }
    }
    else if (options && options.set) {
        request.headers = request.headers || {};
    }
    body = unsigned ? { hash: exports.PAYLOAD_UNSIGNED } : body;
    request = { ...request, url, body };
    if (typeof request.url !== 'string' && !request.url.host) {
        credentials = { serviceName: 's3', ...credentials };
    }
    const result = { ...extra, ...http_1.signRequest(credentials, request, { ...exports.S3_OPTIONS, ...options }) };
    if (options && options.set && isQuery &&
        typeof originalRequest.url === 'string') {
        originalRequest.url = url.toString();
    }
    if (typeof originalRequest.url !== 'string' && !originalRequest.url.host) {
        originalRequest.url.host = url.host;
    }
    return result;
}
exports.signS3Request = signS3Request;
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
function signS3Policy(credentials, policy, options) {
    const ts = options && options.timestamp;
    const cr = { serviceName: 's3', regionName: endpoint_1.DEFAULT_REGION, ...credentials };
    // Get timestamp, derive key, prepare form fields
    const timestamp = (typeof ts === 'string') ? ts : core_1.formatTimestamp(ts);
    const { signing, credential } = core_1.getSigning(timestamp, cr, options);
    const fields = {
        'x-amz-date': timestamp,
        'x-amz-algorithm': core_1.MAIN_ALGORITHM,
        'x-amz-credential': credential,
    };
    // Add the fields to the policy conditions
    const conditions = (policy.conditions || []).concat(Object.keys(fields).map(k => ({ [k]: fields[k] })));
    const finalPolicy = JSON.stringify({ ...policy, conditions });
    // Encode and sign the policy
    const encodedPolicy = Buffer.from(finalPolicy).toString('base64');
    const signature = core_1.signString(signing.key, encodedPolicy).toString('hex');
    return { ...fields, 'policy': encodedPolicy, 'x-amz-signature': signature };
}
exports.signS3Policy = signS3Policy;
const chunked = __importStar(require("./s3_chunked"));
exports.chunked = chunked;
//# sourceMappingURL=s3.js.map