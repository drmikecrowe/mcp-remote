import { describe, it, expect } from 'vitest'
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
