"use strict";
/**
 * Code for signing generic messages using AWS Signature version 4.
 *
 * This module contains only common signing logic (i.e. not HTTP specific);
 * main functions are [[formatTimestamp]] to generate timestamps, [[getSigning]]
 * to derive the signing key, and [[signDigest]] to sign a hash.
 */
/** */
Object.defineProperty(exports, "__esModule", { value: true });
const crypto_1 = require("crypto");
/** Format the date stamp for [[getSigningData]] (low-level). */
function formatDate(date) {
    const str = (date || new Date()).toISOString();
    if (str.length !== 24) {
        throw new Error('Unexpected ISO string when formatting date');
    }
    return str.substring(0, 10).replace(/-/g, '');
}
exports.formatDate = formatDate;
/**
 * Derive the signature key and credential scope (low-level)
 *
 * `dateStamp` can be created with [[formatDate]]. Because it's cropped
 * to 8 characters, a full timestamp (see [[formatTimestamp]]) also works.
 *
 * @returns Signing data (key and credentials scope)
 * @category Key derivation
 */
function getSigningData(dateStamp, secretKey, regionName, serviceName) {
    dateStamp = dateStamp.substring(0, 8);
    const parts = [dateStamp, regionName, serviceName, 'aws4_request'];
    let key = Buffer.from('AWS4' + secretKey);
    for (const part of parts) {
        key = crypto_1.createHmac('sha256', key).update(part).digest();
    }
    return { key, scope: parts.join('/') };
}
exports.getSigningData = getSigningData;
/** Make a simple reuse-previous-result cache for [[getSigningData]] */
getSigningData.makeSimpleCache = () => {
    let key;
    let value;
    return function _cached_getSigningData(a, b, c, d) {
        a = a.substring(0, 8);
        const nkey = [a, b, c, d].join('/');
        if (key !== nkey) {
            [key, value] = [nkey, getSigningData(a, b, c, d)];
        }
        return value;
    };
};
/** Format the timestamp for a request (low-level) */
function formatTimestamp(date) {
    const str = (date || new Date()).toISOString();
    if (str.length !== 24) {
        throw new Error('Unexpected ISO string when formatting date');
    }
    return str.substring(0, 19).replace(/[:-]/g, '') + 'Z';
}
exports.formatTimestamp = formatTimestamp;
/**
 * Sign an arbitrary string using the derived key (low-level)
 *
 * @param sts String to sign
 * @param key The signing key obtained from [[getSigningData]]
 * @returns The binary signature
 * @category Signing
 */
exports.signString = (key, sts) => crypto_1.createHmac('sha256', key).update(sts).digest();
/** Main algorithm ID */
exports.MAIN_ALGORITHM = 'AWS4-HMAC-SHA256';
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
exports.signDigest = (algorithm, payloadDigest, timestamp, signing) => exports.signString(signing.key, [algorithm, timestamp, signing.scope, payloadDigest].join('\n'));
/**
 * Convenience version of [[getSigningData]] that accepts a
 * `Credentials` object, and also returns a credential string.
 *
 * @param dateStamp The timestamp / date stamp
 * @param credentials Credentials to derive from
 * @returns Signing data and credential string
 * @category Key derivation
 */
function getSigning(dateStamp, credentials, options) {
    const { accessKey, secretKey, regionName, serviceName } = credentials;
    const derive = (options && options.getSigningData) || getSigningData;
    const signing = derive(dateStamp, secretKey, regionName, serviceName);
    return { signing, credential: `${accessKey}/${signing.scope}` };
}
exports.getSigning = getSigning;
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
function sign(credentials, algorithm, payloadDigest, timestamp, options) {
    const { signing, credential } = getSigning(timestamp, credentials, options);
    const signature = exports.signDigest(algorithm, payloadDigest, timestamp, signing);
    return { signature, credential };
}
exports.sign = sign;
//# sourceMappingURL=core.js.map