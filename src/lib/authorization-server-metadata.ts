import { debugLog, log } from './utils'
import { isSafeMetadataUrl } from './url-safety'

/**
 * Validates the shape of an Authorization Server Metadata response from an
 * untrusted server (issue #8). `issuer` must be a string; malformed
 * scopes_supported is dropped rather than trusted.
 */
function validateAuthorizationServerMetadata(data: unknown): AuthorizationServerMetadata | undefined {
  if (typeof data !== 'object' || data === null) return undefined
  const obj = data as Record<string, unknown>
  if (typeof obj.issuer !== 'string') {
    debugLog('Authorization Server Metadata missing string issuer')
    return undefined
  }
  const isStringArray = (v: unknown): v is string[] => Array.isArray(v) && v.every((x) => typeof x === 'string')
  const metadata = { ...obj } as AuthorizationServerMetadata
  if (obj.scopes_supported !== undefined && !isStringArray(obj.scopes_supported)) {
    debugLog('Dropping malformed scopes_supported in Authorization Server Metadata')
    delete (metadata as Record<string, unknown>).scopes_supported
  }
  return metadata
}

/**
 * OAuth 2.0 Authorization Server Metadata as defined in RFC 8414
 * https://datatracker.ietf.org/doc/html/rfc8414#section-2
 */
export interface AuthorizationServerMetadata {
  /** The authorization server's issuer identifier */
  issuer: string
  /** URL of the authorization server's authorization endpoint */
  authorization_endpoint?: string
  /** URL of the authorization server's token endpoint */
  token_endpoint?: string
  /** JSON array containing a list of the OAuth 2.0 scope values that this server supports */
  scopes_supported?: string[]
  /** JSON array containing a list of the OAuth 2.0 response_type values that this server supports */
  response_types_supported?: string[]
  /** JSON array containing a list of the OAuth 2.0 grant type values that this server supports */
  grant_types_supported?: string[]
  /** JSON array containing a list of client authentication methods supported by this token endpoint */
  token_endpoint_auth_methods_supported?: string[]
  /** Additional metadata fields */
  [key: string]: unknown
}

/**
 * Constructs the well-known URL for OAuth authorization server metadata
 * @param serverUrl The base server URL
 * @returns The well-known metadata URL
 */
export function getMetadataUrl(serverUrl: string): string {
  const url = new URL(serverUrl)
  // Per RFC 8414, the metadata is at /.well-known/oauth-authorization-server
  // relative to the issuer identifier
  const metadataPath = '/.well-known/oauth-authorization-server'

  // Construct the full metadata URL
  return `${url.origin}${metadataPath}`
}

/**
 * Fetches OAuth 2.0 Authorization Server Metadata from the well-known endpoint
 * @param serverUrl The server URL to fetch metadata for
 * @returns The authorization server metadata, or undefined if fetch fails
 */
export async function fetchAuthorizationServerMetadata(serverUrl: string): Promise<AuthorizationServerMetadata | undefined> {
  const metadataUrl = getMetadataUrl(serverUrl)

  debugLog('Fetching authorization server metadata', { serverUrl, metadataUrl })

  // SSRF guard (issue #7): serverUrl may be an authorization server discovered
  // from server-controlled Protected Resource Metadata.
  if (!isSafeMetadataUrl(metadataUrl)) {
    debugLog('Refusing to fetch unsafe authorization server metadata URL', { metadataUrl })
    return undefined
  }

  try {
    const response = await fetch(metadataUrl, {
      headers: {
        Accept: 'application/json',
      },
      // Short timeout to avoid blocking
      signal: AbortSignal.timeout(5000),
    })

    if (!response.ok) {
      if (response.status === 404) {
        debugLog('Authorization server metadata endpoint not found (404)', { metadataUrl })
      } else {
        debugLog('Failed to fetch authorization server metadata', {
          status: response.status,
          statusText: response.statusText,
        })
      }
      return undefined
    }

    const metadata = validateAuthorizationServerMetadata(await response.json())
    if (!metadata) {
      debugLog('Authorization server metadata failed validation', { metadataUrl })
      return undefined
    }

    // RFC 8414 §3.3 issuer binding (issue #8): the issuer should match the origin
    // the metadata was fetched from. Warn (rather than hard-fail) to avoid breaking
    // legitimately-configured-but-sloppy servers, while surfacing token-confusion risk.
    try {
      if (new URL(metadata.issuer).origin !== new URL(metadataUrl).origin) {
        log(`Warning: authorization server issuer "${metadata.issuer}" does not match metadata origin ${new URL(metadataUrl).origin}`)
      }
    } catch {
      log(`Warning: authorization server issuer "${metadata.issuer}" is not a valid URL`)
    }

    debugLog('Successfully fetched authorization server metadata', {
      issuer: metadata.issuer,
      scopes_supported: metadata.scopes_supported,
      scopeCount: metadata.scopes_supported?.length || 0,
    })

    return metadata
  } catch (error) {
    debugLog('Error fetching authorization server metadata', {
      error: error instanceof Error ? error.message : String(error),
      metadataUrl,
    })
    return undefined
  }
}
