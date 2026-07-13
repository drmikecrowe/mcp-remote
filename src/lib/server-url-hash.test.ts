import { describe, it, expect } from 'vitest'
import crypto from 'crypto'
import { getServerUrlHash } from './utils'

/**
 * SEC-7 — MD5 used for the credential-namespace hash.
 *
 * The hash names the on-disk credential files. MD5 is collision-prone and trips
 * security scanners; SHA-256 removes both problems. This is not a confidentiality
 * boundary, so the change is about hygiene and scanner cleanliness rather than a
 * live exploit.
 */
describe('getServerUrlHash uses SHA-256 (SEC-7)', () => {
  it('produces a SHA-256 digest, not an MD5 one', () => {
    // When a server URL is hashed
    const hash = getServerUrlHash('https://example.com/sse')

    // Then the digest is SHA-256 (64 hex chars), not MD5 (32)
    expect(hash).toMatch(/^[0-9a-f]{64}$/)
    expect(hash).not.toBe(crypto.createHash('md5').update('https://example.com/sse').digest('hex'))
  })

  it('still isolates credentials per server, resource and headers', () => {
    // Given the same server reached with different resources / headers
    const base = getServerUrlHash('https://example.com/sse')
    const withResource = getServerUrlHash('https://example.com/sse', 'https://tenant1.example.com/')
    const withHeaders = getServerUrlHash('https://example.com/sse', undefined, { Authorization: 'Bearer a' })

    // Then each configuration still gets its own credential namespace (the #25 behaviour)
    expect(new Set([base, withResource, withHeaders]).size).toBe(3)
  })

  it('is deterministic', () => {
    // Given the same inputs
    // Then the same namespace is produced, so credentials are found again on the next run
    expect(getServerUrlHash('https://example.com/sse')).toBe(getServerUrlHash('https://example.com/sse'))
  })
})
