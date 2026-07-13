import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { fetchAuthorizationServerMetadata } from './authorization-server-metadata'
import { isSafeMetadataUrl } from './url-safety'

describe('url-safety', () => {
  describe('isSafeMetadataUrl', () => {
    it('allows https URLs', () => {
      expect(isSafeMetadataUrl('https://auth.example.com/.well-known/oauth-authorization-server')).toBe(true)
    })

    it('allows http to localhost (dev servers)', () => {
      expect(isSafeMetadataUrl('http://localhost:8080/.well-known/x')).toBe(true)
      expect(isSafeMetadataUrl('http://127.0.0.1:8080/.well-known/x')).toBe(true)
    })

    it('blocks non-http(s) schemes (file://, gopher://, data:)', () => {
      expect(isSafeMetadataUrl('file:///etc/passwd')).toBe(false)
      expect(isSafeMetadataUrl('gopher://evil/')).toBe(false)
      expect(isSafeMetadataUrl('data:text/plain,hi')).toBe(false)
    })

    it('blocks cloud instance-metadata / link-local endpoints (SSRF)', () => {
      expect(isSafeMetadataUrl('http://169.254.169.254/latest/meta-data/iam/security-credentials/')).toBe(false)
      expect(isSafeMetadataUrl('https://169.254.169.254/')).toBe(false)
      expect(isSafeMetadataUrl('http://100.100.100.200/')).toBe(false)
      expect(isSafeMetadataUrl('http://[fe80::1]/')).toBe(false)
    })

    it('rejects malformed URLs', () => {
      expect(isSafeMetadataUrl('not a url')).toBe(false)
      expect(isSafeMetadataUrl('')).toBe(false)
    })
  })
})

/**
 * The predicate above is only useful if the fetch sites actually consult it.
 * These assert the request is never made, rather than merely that the result is undefined.
 */
describe('SSRF guard is enforced at the metadata fetch sites (SEC-9)', () => {
  // vi.spyOn cannot express fetch's overloads; the spy is only used for call assertions
  let fetchSpy: any

  beforeEach(() => {
    fetchSpy = vi.spyOn(globalThis, 'fetch')
  })

  afterEach(() => {
    fetchSpy.mockRestore()
  })

  it('never requests the cloud instance-metadata endpoint for AS metadata', async () => {
    // Given a malicious server that points discovery at the IMDS endpoint,
    // where a cloud VM's IAM credentials live
    const result = await fetchAuthorizationServerMetadata('http://169.254.169.254')

    // Then no request is made at all — the SSRF is not merely ignored, it never happens
    expect(fetchSpy).not.toHaveBeenCalled()
    expect(result).toBeUndefined()
  })

  it('never opens a file:// URL for AS metadata', async () => {
    // Given a server pointing discovery at the local filesystem
    const result = await fetchAuthorizationServerMetadata('file:///etc/passwd')

    // Then no request is made
    expect(fetchSpy).not.toHaveBeenCalled()
    expect(result).toBeUndefined()
  })

  it('still fetches a legitimate https authorization server', async () => {
    // Given a normal https authorization server
    fetchSpy.mockResolvedValue(new Response(JSON.stringify({ issuer: 'https://auth.example.com' }), { status: 200 }))

    // When metadata is fetched
    await fetchAuthorizationServerMetadata('https://auth.example.com')

    // Then the guard does not get in the way of the happy path
    expect(fetchSpy).toHaveBeenCalledTimes(1)
  })
})
