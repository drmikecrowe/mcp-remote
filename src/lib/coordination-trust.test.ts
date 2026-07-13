import { describe, it, expect, afterEach } from 'vitest'
import express from 'express'
import { EventEmitter } from 'events'
import { AddressInfo } from 'net'
import { Server } from 'http'
import { isLockValid, waitForAuthentication } from './coordination'
import { setupOAuthCallbackServerWithLongPoll } from './utils'

/**
 * SEC-5 — Lockfile trust: PID reuse / fake port redirects coordination.
 *
 * coordinateAuth() trusts any lockfile it finds: if the PID is live and the port
 * answers /wait-for-auth, it hands the auth flow to whatever is listening there.
 * A recycled PID/port, or a lockfile planted by another local process, could stand
 * in for the real primary. The lockfile now carries a per-instance secret that the
 * genuine primary echoes back on /wait-for-auth.
 */
describe('Lockfile secret validation (SEC-5)', () => {
  const servers: Server[] = []

  const impostor = async (echoSecret?: string): Promise<number> => {
    const app = express()
    app.get('/wait-for-auth', (_req, res) => {
      if (echoSecret) res.setHeader('X-MCP-Auth-Secret', echoSecret)
      res.status(200).send('Authentication completed')
    })
    const server = app.listen(0, '127.0.0.1')
    servers.push(server)
    await new Promise<void>((resolve) => server.on('listening', () => resolve()))
    return (server.address() as AddressInfo).port
  }

  const lock = (port: number, secret?: string) => ({
    pid: process.pid, // a live PID — the old check would stop here and trust it
    port,
    timestamp: Date.now(),
    secret,
  })

  afterEach(() => {
    servers.forEach((s) => s.close())
    servers.length = 0
  })

  it('rejects a server that cannot echo the lockfile secret', async () => {
    // Given a lockfile naming a secret, but the port is answered by something else —
    // a recycled port, or a process that planted the lockfile and is now impersonating
    const port = await impostor(undefined)

    // When the lockfile is validated
    const valid = await isLockValid(lock(port, 'the-real-secret'))

    // Then it is refused, even though the PID is live and the endpoint returns 200
    expect(valid).toBe(false)
  })

  it('rejects a server that echoes the wrong secret', async () => {
    // Given an impostor guessing at the secret
    const port = await impostor('wrong-secret')

    // When the lockfile is validated
    const valid = await isLockValid(lock(port, 'the-real-secret'))

    // Then it is refused
    expect(valid).toBe(false)
  })

  it('accepts the genuine primary that echoes the secret', async () => {
    // Given the real auth instance, which knows its own secret
    const port = await impostor('the-real-secret')

    // When the lockfile is validated
    const valid = await isLockValid(lock(port, 'the-real-secret'))

    // Then coordination proceeds as normal
    expect(valid).toBe(true)
  })

  it('stays compatible with a lockfile written before this fix', async () => {
    // Given a lockfile from an older version, which carries no secret
    const port = await impostor(undefined)

    // When it is validated
    const valid = await isLockValid(lock(port, undefined))

    // Then the old behaviour is preserved rather than breaking a live handoff
    expect(valid).toBe(true)
  })

  it('bails out of polling when the peer stops echoing the secret', async () => {
    // Given a peer that answers /wait-for-auth but is not the instance we locked against
    const port = await impostor('not-our-secret')

    // When we poll it, expecting our own secret
    const completed = await waitForAuthentication(port, 'our-secret')

    // Then we take over rather than waiting on an impostor to finish "authenticating"
    expect(completed).toBe(false)
  })

  it('echoes its own secret on /wait-for-auth so peers can verify it', async () => {
    // Given the real callback server, started with a per-instance secret
    const { server } = setupOAuthCallbackServerWithLongPoll({
      port: 0,
      path: '/oauth/callback',
      events: new EventEmitter(),
      authSecret: 'my-instance-secret',
    })
    servers.push(server)
    await new Promise<void>((resolve) => server.on('listening', () => resolve()))
    const port = (server.address() as AddressInfo).port

    // When a peer polls it
    const res = await fetch(`http://127.0.0.1:${port}/wait-for-auth?poll=false`)

    // Then the secret comes back, which is what lets the peer trust this instance
    expect(res.headers.get('x-mcp-auth-secret')).toBe('my-instance-secret')
  })
})
