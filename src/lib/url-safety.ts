/**
 * SSRF guard for URLs discovered from remote (potentially untrusted) MCP server
 * metadata — e.g. the `resource_metadata` URL in a WWW-Authenticate header or the
 * `authorization_servers` entries in Protected Resource Metadata.
 *
 * Blocks the two concrete exploit classes named in SECURITY-AUDIT.md (SEC-9):
 *  - non-http(s) schemes such as `file://` (local file read)
 *  - link-local / cloud instance-metadata endpoints such as 169.254.169.254 (IMDS)
 *
 * Intentionally conservative: it does NOT resolve DNS (so a hostname that resolves
 * to a private IP is not caught) and it does NOT block general RFC-1918 ranges,
 * because legitimate corporate deployments live on private networks. The real
 * mitigation remains connecting only to trusted servers; this closes the
 * highest-value, lowest-false-positive holes.
 *
 * @param urlStr The URL to validate
 * @returns true if the URL is safe to fetch, false if it should be refused
 */
export function isSafeMetadataUrl(urlStr: string): boolean {
  let url: URL
  try {
    url = new URL(urlStr)
  } catch {
    return false
  }

  // Only http(s) — blocks file:, gopher:, data:, etc.
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    return false
  }

  // Strip brackets from IPv6 literals for comparison
  const host = url.hostname.replace(/^\[|\]$/g, '').toLowerCase()

  // Block link-local / cloud instance-metadata endpoints (IMDS)
  if (host.startsWith('169.254.')) return false // IPv4 link-local (AWS/Azure/GCP IMDS)
  if (host === '100.100.100.200') return false // Alibaba Cloud metadata
  if (host.startsWith('fe80:')) return false // IPv6 link-local

  return true
}
