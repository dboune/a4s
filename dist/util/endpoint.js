"use strict";
/**
 * Utilities for inferring service / region from endpoints (hosts)
 * and vice versa.
 */
Object.defineProperty(exports, "__esModule", { value: true });
/** Default region for AWS requests */
exports.DEFAULT_REGION = 'us-east-1';
exports.ENDPOINT_OVERRIDES = {
    ses: 'email',
};
exports.SERVICE_OVERRIDES = {
    email: 'ses',
};
const isRegion = (x) => /^[a-z]{1,3}-[a-z]+-\d{1,2}$/i.test(x);
/**
 * Infer serviceName / regionName from an endpoint host, for signing.
 * The port (if any) will be ignored.
 * Note: If host doesn't specify a region *and* there's a subdomain,
 * this may not work.
 */
function parseHost(host) {
    // Match RE
    const match = host && /(^|\.)(([\w-]+)\.)?([\w-]+)\.amazonaws\.com(\.cn)?(\:\d+)?$/i.exec(host);
    if (!match) {
        throw new Error(`Hostname '${host}' can't be parsed to extract region/service info`);
    }
    // Extract parts
    let [serviceName, regionName] = [match[4], match[3]].map(x => x && x.toLowerCase());
    if (regionName) {
        if (isRegion(serviceName)) {
            [serviceName, regionName] = [regionName, serviceName];
        }
        else if (!isRegion(regionName)) {
            regionName = exports.DEFAULT_REGION;
        }
    }
    else {
        regionName = exports.DEFAULT_REGION;
    }
    // Detect S3 style regions
    if (/^s3-/.test(serviceName) && isRegion(serviceName.substring(3))) {
        [serviceName, regionName] = ['s3', serviceName.substring(3)];
    }
    // Correct service name
    if (/-fips$/.test(serviceName)) {
        serviceName = serviceName.substring(0, serviceName.length - 5);
    }
    if ({}.hasOwnProperty.call(exports.SERVICE_OVERRIDES, serviceName)) {
        serviceName = exports.SERVICE_OVERRIDES[serviceName];
    }
    return { regionName, serviceName };
}
exports.parseHost = parseHost;
/**
 * Obtain the (most common) endpoint for a service on a region.
 * This uses the `<service>.<region>` format.
 */
function formatHost(serviceName, regionName, port) {
    if ({}.hasOwnProperty.call(exports.ENDPOINT_OVERRIDES, serviceName)) {
        serviceName = exports.ENDPOINT_OVERRIDES[serviceName];
    }
    regionName = regionName ? '.' + regionName : '';
    return `${serviceName}${regionName}.amazonaws.com` + (port ? `:${port}` : '');
}
exports.formatHost = formatHost;
//# sourceMappingURL=endpoint.js.map