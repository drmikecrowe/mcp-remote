import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { fetchAuthorizationServerMetadata } from './authorization-server-metadata'

/**
 * SEC-12 — No runtime schema validation on remote metadata.
 * SEC-13 — RFC 8414 issuer binding not verified.
 *
 * Both metadata fetches used a bare `as Type` cast on response.json(), so whatever the
 * remote server returned flowed straight into URL construction and `.join(' ')`.
 */
describe('Remote metadata validation (SEC-12, SEC-13)', () => {
  // vi.spyOn cannot express fetch's overloads; the spy is only used for call assertions
  let fetchSpy: any
  let stderr: ReturnType<typeof vi.spyOn>

  const respond = (body: unknown) => fetchSpy.mockResolvedValue(new Response(JSON.stringify(body), { status: 200 }))
  const logged = () => stderr.mock.calls.flat().join(' ')

  beforeEach(() => {
    fetchSpy = vi.spyOn(globalThis, 'fetch')
    stderr = vi.spyOn(console, 'error').mockImplementation(() => {})
  })

  afterEach(() => {
    fetchSpy.mockRestore()
    stderr.mockRestore()
  })

  it('rejects metadata that is not an object at all (SEC-12)', async () => {
    // Given a server returning a bare string where an object is expected
    respond('not-an-object')

    // When metadata is fetched
    const metadata = await fetchAuthorizationServerMetadata('https://auth.example.com')

    // Then it is refused rather than cast and used
    expect(metadata).toBeUndefined()
  })

  it('rejects metadata with no string issuer (SEC-12)', async () => {
    // Given metadata whose issuer is the wrong type
    respond({ issuer: 12345 })

    // When metadata is fetched
    const metadata = await fetchAuthorizationServerMetadata('https://auth.example.com')

    // Then it is refused — issuer flows into URL construction downstream
    expect(metadata).toBeUndefined()
  })

  it('drops a malformed scopes_supported instead of trusting it (SEC-12)', async () => {
    // Given scopes_supported that is not an array of strings; unguarded, this reaches
    // a .join(' ') that would stringify objects into the requested scope
    respond({ issuer: 'https://auth.example.com', scopes_supported: [{ evil: true }, 42] })

    // When metadata is fetched
    const metadata = await fetchAuthorizationServerMetadata('https://auth.example.com')

    // Then the good part survives and the malformed field is dropped
    expect(metadata?.issuer).toBe('https://auth.example.com')
    expect(metadata?.scopes_supported).toBeUndefined()
  })

  it('keeps a well-formed scopes_supported', async () => {
    // Given legitimate metadata
    respond({ issuer: 'https://auth.example.com', scopes_supported: ['openid', 'email'] })

    // When metadata is fetched
    const metadata = await fetchAuthorizationServerMetadata('https://auth.example.com')

    // Then validation does not get in the way of the happy path
    expect(metadata?.scopes_supported).toEqual(['openid', 'email'])
  })

  it('warns when the issuer does not match the origin it was fetched from (SEC-13)', async () => {
    // Given metadata served by auth.example.com but claiming to be issued by attacker.com
    respond({ issuer: 'https://attacker.com' })

    // When metadata is fetched
    await fetchAuthorizationServerMetadata('https://auth.example.com')

    // Then the issuer/origin mismatch is surfaced (RFC 8414 §3.3 — token confusion)
    expect(logged()).toContain('does not match metadata origin')
  })

  it('stays quiet when the issuer matches the origin (SEC-13)', async () => {
    // Given a correctly-configured authorization server
    respond({ issuer: 'https://auth.example.com' })

    // When metadata is fetched
    await fetchAuthorizationServerMetadata('https://auth.example.com')

    // Then no warning is raised, so the warning stays meaningful when it does appear
    expect(logged()).not.toContain('does not match metadata origin')
  })
})
