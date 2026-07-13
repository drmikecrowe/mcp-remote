import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { parseCommandLineArgs } from './utils'

/**
 * SEC-8  — `--host` sets redirect URI but the server stays on loopback (INFO, footgun).
 * SEC-14 — `--allow-http` has no runtime warning (LOW).
 *
 * Both are cases where mcp-remote silently did something the user probably did not
 * intend. Neither is exploitable on its own; the fix is to say so out loud.
 */
describe('CLI safety warnings (SEC-8, SEC-14)', () => {
  let stderr: ReturnType<typeof vi.spyOn>
  const logged = () => stderr.mock.calls.flat().join(' ')

  beforeEach(() => {
    stderr = vi.spyOn(console, 'error').mockImplementation(() => {})
  })

  afterEach(() => {
    stderr.mockRestore()
  })

  it('warns that --allow-http sends tokens in the clear (SEC-14)', async () => {
    // Given a user downgrading to plaintext HTTP
    await parseCommandLineArgs(['https://example.com/sse', '--allow-http'], 'test usage')

    // Then the consequence is stated rather than left implicit
    expect(logged()).toContain('--allow-http is set')
    expect(logged()).toContain('unencrypted HTTP')
  })

  it('stays quiet when --allow-http is absent (SEC-14)', async () => {
    // Given the default, secure configuration
    await parseCommandLineArgs(['https://example.com/sse'], 'test usage')

    // Then no warning, so the warning stays meaningful when it does fire
    expect(logged()).not.toContain('--allow-http is set')
  })

  it('warns that a non-loopback --host cannot receive the callback (SEC-8)', async () => {
    // Given a --host that the callback server will never listen on
    await parseCommandLineArgs(['https://example.com/sse', '--host', 'example.internal'], 'test usage')

    // Then the user is told the authorization code will not come back to this process
    expect(logged()).toContain('only listens on 127.0.0.1')
  })

  it('stays quiet for a loopback --host (SEC-8)', async () => {
    // Given a --host the callback server does listen on
    await parseCommandLineArgs(['https://example.com/sse', '--host', '127.0.0.1'], 'test usage')

    // Then there is nothing to warn about
    expect(logged()).not.toContain('only listens on 127.0.0.1')
  })

  it('accepts a valid absolute --resource', async () => {
    // Given an RFC 8707-conformant resource indicator
    const result = await parseCommandLineArgs(['https://example.com/sse', '--resource', 'https://tenant1.example.com/'], 'test usage')

    // Then it is used
    expect(result.authorizeResource).toBe('https://tenant1.example.com/')
  })
})
