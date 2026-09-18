/* Copyright (c) 2025 Voxgig Ltd, MIT License */

import { SekretoError } from '../src/provider/support'

const HTTP_TIMEOUT_MS = 10000

const HTTP_MAXBODY = 8 * 1024 * 1024

export async function fetchjson(
  method: string,
  url: string,
  headers: Record<string, string>,
  body?: string,
): Promise<{ status: number; body: any }> {
  let res: Response
  try {
    res = await fetch(url, {
      method,
      headers,
      body,
      // A vault API never legitimately redirects, and a followed redirect
      // carries X-Vault-Token to the redirect's host (and can downgrade
      // https to http), which checkaddr - it only validates the configured
      // address - cannot see. Refuse to follow one.
      redirect: 'error',
      signal: AbortSignal.timeout(HTTP_TIMEOUT_MS),
    })
  } catch (err: any) {
    throw new SekretoError('sekreto: cannot reach ' + url.split('?')[0] + ': ' + err.message)
  }

  let text = ''
  try {
    const decoder = new TextDecoder()
    let size = 0

    for await (const chunk of res.body ?? []) {
      size += chunk.length
      if (HTTP_MAXBODY < size) {
        throw new SekretoError('sekreto: oversized response from ' + url.split('?')[0])
      }
      text += decoder.decode(chunk, { stream: true })
    }
    text += decoder.decode()
  } catch (err: any) {
    if (err instanceof SekretoError) {
      throw err
    }
    throw new SekretoError('sekreto: cannot reach ' + url.split('?')[0] + ': ' + err.message)
  }

  let parsed: any = undefined
  try {
    parsed = JSON.parse(text)
  } catch (err: any) {
    if (200 === res.status) {
      throw new SekretoError('sekreto: malformed response from ' + url.split('?')[0])
    }
  }

  return { status: res.status, body: parsed }
}
