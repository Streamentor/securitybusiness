/** Static text only. Never persist upstream bodies, arbitrary exception text or credentials. */
/**
 * @param {import("./website-scan-failure.ts").WebsiteFailureCode} code
 * @param {number} [httpStatus]
 * @param {import("./website-scan-failure.ts").WebsiteFailure["provider"]} [provider]
 * @returns {import("./website-scan-failure.ts").WebsiteFailure}
 */
export function websiteFailure(code, httpStatus, provider) {
  const messages = {
    timeout: "The website did not finish responding within the scanner's time limit. Try again or check your server and firewall logs.",
    dns: "The scanner could not resolve the website hostname. Check its public DNS records, then try again.",
    tls: "The scanner could not establish a trusted HTTPS connection. Check the certificate and TLS configuration.",
    blocked: `The website refused the scanner's request${httpStatus ? ` (HTTP ${httpStatus})` : ""}${provider ? ` at ${provider}` : ""}. Check your firewall rules for ScanMySaaS-Scanner/2.0.`,
    "http-error": `The website returned an unsuccessful response${httpStatus ? ` (HTTP ${httpStatus})` : ""}. Check the URL and server logs.`,
    "not-html": "The URL did not return a public HTML page. Enter the public app URL rather than an API, download or login-only endpoint.",
    "empty-html": "The URL returned no readable HTML content. Check the public app URL and try again.",
    "response-too-large": "The website response exceeded the scanner's 2 MB safety limit. Try a smaller public page.",
    redirect: "The URL redirected to another hostname or exceeded the redirect limit. Enter the final app URL you own or are authorized to test.",
    network: "The scanner could not connect to the website. The server may be unavailable or blocking data-center requests; check its logs and try again.",
    internal: "The scan could not finish because of a scanner or storage error. Please try again. Any reserved scan credit is returned when the failed job is handled.",
  };
  return {code, message: messages[code], ...(httpStatus ? {httpStatus} : {}), ...(provider ? {provider} : {})};
}

