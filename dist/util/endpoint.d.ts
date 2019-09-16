/**
 * Utilities for inferring service / region from endpoints (hosts)
 * and vice versa.
 */
/** Default region for AWS requests */
export declare const DEFAULT_REGION = "us-east-1";
export declare const ENDPOINT_OVERRIDES: {
    [key: string]: string;
};
export declare const SERVICE_OVERRIDES: {
    [key: string]: string;
};
/**
 * Infer serviceName / regionName from an endpoint host, for signing.
 * The port (if any) will be ignored.
 * Note: If host doesn't specify a region *and* there's a subdomain,
 * this may not work.
 */
export declare function parseHost(host: string): {
    regionName: string;
    serviceName: string;
};
/**
 * Obtain the (most common) endpoint for a service on a region.
 * This uses the `<service>.<region>` format.
 */
export declare function formatHost(serviceName: string, regionName?: string, port?: number | string): string;
