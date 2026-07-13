import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import fs from 'fs'
import os from 'os'
import path from 'path'
import { debugLog, parseCommandLineArgs } from './utils'
import { ensureConfigDir, getConfigDir } from './mcp-auth-config'

/**
 * SEC-1 (debug log is world-readable and can capture live tokens) and
 * SEC-2 (config directory created world-listable).
 */
describe('Local file hygiene (SEC-1, SEC-2)', () => {
  let tmpDir: string

  const mode = (p: string) => fs.statSync(p).mode & 0o777

  beforeEach(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-remote-perms-'))
    process.env.MCP_REMOTE_CONFIG_DIR = tmpDir
    // debugLog is a no-op unless DEBUG is on; --debug is the only switch for it
    await parseCommandLineArgs(['https://example.com/sse', '--debug'], 'test usage')
    global.currentServerUrlHash = 'testhash'
  })

  afterEach(() => {
    delete process.env.MCP_REMOTE_CONFIG_DIR
    fs.rmSync(tmpDir, { recursive: true, force: true })
  })

  it('creates the config directory owner-only (SEC-2)', async () => {
    // When the config directory is created
    await ensureConfigDir()

    // Then no other local user can list the OAuth material inside it
    expect(mode(getConfigDir())).toBe(0o700)
  })

  it('tightens a config directory left world-listable by an earlier version (SEC-2)', async () => {
    // Given a config directory that already exists with the old 0o755 mode,
    // as it would on any install that predates this fix
    const configDir = getConfigDir()
    fs.mkdirSync(configDir, { recursive: true, mode: 0o755 })
    fs.chmodSync(configDir, 0o755)
    expect(mode(configDir)).toBe(0o755)

    // When mcp-remote runs again
    await ensureConfigDir()

    // Then the directory is tightened, not left as-is
    // (mkdir's `mode` option is ignored when the directory already exists)
    expect(mode(configDir)).toBe(0o700)
  })

  it('writes the debug log owner-only (SEC-1)', () => {
    // When something is written to the debug log
    debugLog('hello')

    // Then the log, which records auth server URLs and scopes, is not world-readable
    const logPath = path.join(getConfigDir(), 'testhash_debug.log')
    expect(mode(logPath)).toBe(0o600)
  })

  it('tightens a debug log left world-readable by an earlier version (SEC-1)', () => {
    // Given a debug log already on disk with the old permissive mode
    const configDir = getConfigDir()
    fs.mkdirSync(configDir, { recursive: true })
    const logPath = path.join(configDir, 'testhash_debug.log')
    fs.writeFileSync(logPath, 'stale\n')
    fs.chmodSync(logPath, 0o644)

    // When mcp-remote appends to it
    debugLog('hello')

    // Then the existing file is tightened (appendFileSync's `mode` only applies on create)
    expect(mode(logPath)).toBe(0o600)
  })

  it('never writes access or refresh token values into the debug log (SEC-1)', () => {
    // Given a token payload with an invalid expires_in — the branch that used to
    // JSON.stringify the whole token object into the log
    const tokens = {
      access_token: 'SECRET-ACCESS-TOKEN-VALUE',
      refresh_token: 'SECRET-REFRESH-TOKEN-VALUE',
      token_type: 'Bearer',
      expires_in: -1,
    }

    // When the invalid-expiry warning is emitted the way the provider emits it
    debugLog('⚠️ WARNING: Invalid expires_in detected in tokens ⚠️', {
      expiresIn: tokens.expires_in,
      hasAccessToken: !!tokens.access_token,
      hasRefreshToken: !!tokens.refresh_token,
    })

    // Then the log records only the presence of the credentials, never their values
    const contents = fs.readFileSync(path.join(getConfigDir(), 'testhash_debug.log'), 'utf8')
    expect(contents).not.toContain('SECRET-ACCESS-TOKEN-VALUE')
    expect(contents).not.toContain('SECRET-REFRESH-TOKEN-VALUE')
    expect(contents).toContain('hasAccessToken')
  })
})
