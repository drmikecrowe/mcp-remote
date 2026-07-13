import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { redactSensitiveHeaders, parseCommandLineArgs } from './utils'

/**
 * SEC-3 — Literal header secrets logged to stderr.
 */
describe('Header redaction (SEC-3)', () => {
  describe('redactSensitiveHeaders', () => {
    it('masks credential-bearing headers', () => {
      // Given headers carrying live credentials
      const headers = {
        Authorization: 'Bearer sk-live-abcdef123456',
        Cookie: 'session=deadbeef',
        'X-Api-Key': 'key-abc',
        'Proxy-Authorization': 'Basic dXNlcjpwYXNz',
      }

      // When they are prepared for logging
      const redacted = redactSensitiveHeaders(headers)

      // Then no secret value survives
      expect(Object.values(redacted)).toEqual(['[REDACTED]', '[REDACTED]', '[REDACTED]', '[REDACTED]'])
      expect(JSON.stringify(redacted)).not.toContain('sk-live-abcdef123456')
    })

    it('matches header names case-insensitively', () => {
      // Given a lowercase header name, as a user could easily pass it
      // When redacted
      const redacted = redactSensitiveHeaders({ authorization: 'Bearer sk-live-xyz' })

      // Then it is still masked
      expect(redacted.authorization).toBe('[REDACTED]')
    })

    it('leaves non-sensitive headers readable', () => {
      // Given ordinary headers that are useful in logs
      // When redacted
      const redacted = redactSensitiveHeaders({ 'Content-Type': 'application/json', Accept: 'text/event-stream' })

      // Then they pass through unchanged, so the log stays useful for debugging
      expect(redacted).toEqual({ 'Content-Type': 'application/json', Accept: 'text/event-stream' })
    })

    it('does not mutate the caller’s headers', () => {
      // Given the real headers that will actually be sent to the server
      const headers = { Authorization: 'Bearer sk-live-xyz' }

      // When they are redacted for logging
      redactSensitiveHeaders(headers)

      // Then the original is untouched — redaction is for the log, not the request
      expect(headers.Authorization).toBe('Bearer sk-live-xyz')
    })
  })

  describe('parseCommandLineArgs', () => {
    let stderr: ReturnType<typeof vi.spyOn>

    beforeEach(() => {
      stderr = vi.spyOn(console, 'error').mockImplementation(() => {})
    })

    afterEach(() => {
      stderr.mockRestore()
    })

    it('never echoes a literal --header bearer token to stderr', async () => {
      // Given a literal secret passed on the command line
      const args = ['https://example.com/sse', '--header', 'Authorization: Bearer sk-live-SUPERSECRET']

      // When the arguments are parsed
      const result = await parseCommandLineArgs(args, 'test usage')

      // Then the secret is still sent to the server...
      expect(result.headers['Authorization']).toBe('Bearer sk-live-SUPERSECRET')

      // ...but never appears in anything written to the terminal or debug log
      const logged = stderr.mock.calls.flat().join(' ')
      expect(logged).not.toContain('sk-live-SUPERSECRET')
      expect(logged).toContain('[REDACTED]')
    })
  })
})
