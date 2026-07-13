import { describe, it, expect } from 'vitest'
import { parseCommandLineArgs, buildClientName } from './utils'

describe('Feature: OAuth client name', () => {
  it('parses --client-name', async () => {
    // Given a name for this instance
    const result = await parseCommandLineArgs(['https://example.com/sse', '--client-name', 'Jira - Acme'], 'test usage')

    // Then it is available to the registration call
    expect(result.clientName).toBe('Jira - Acme')
  })

  it('defaults to empty, leaving the fallback to the call site', async () => {
    // Given no --client-name
    const result = await parseCommandLineArgs(['https://example.com/sse'], 'test usage')

    // Then the entrypoint decides the default (MCP CLI Proxy vs MCP CLI Client)
    expect(result.clientName).toBe('')
  })

  it('falls back to the entrypoint default when nothing is provided', () => {
    // Given neither a client name nor a resource
    // Then the previous behaviour is preserved exactly
    expect(buildClientName('', 'MCP CLI Proxy', '')).toBe('MCP CLI Proxy')
  })

  it('appends the resource so instances are distinguishable', () => {
    // Given two tenants of the same server, the consent screen would otherwise show
    // "MCP CLI Proxy" for both
    // Then the resource disambiguates them
    expect(buildClientName('', 'MCP CLI Proxy', 'https://tenant1.atlassian.net/')).toBe('MCP CLI Proxy (https://tenant1.atlassian.net/)')
  })

  it('lets an explicit name replace the default label', () => {
    // Given an explicit --client-name
    // Then it is used verbatim
    expect(buildClientName('Jira - Acme', 'MCP CLI Proxy', '')).toBe('Jira - Acme')
  })

  it('appends the resource to an explicit name too', () => {
    // Given both --client-name and --resource
    // Then the resource is still appended, so tenants stay distinguishable
    expect(buildClientName('Jira - Acme', 'MCP CLI Proxy', 'https://acme.atlassian.net/')).toBe('Jira - Acme (https://acme.atlassian.net/)')
  })
})
