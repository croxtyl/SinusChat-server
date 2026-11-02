// SinusChat — serwer. Copyright © 2026 Sinusoide Technology. SPDX-License-Identifier: AGPL-3.0-only

'use strict'

const jwt = require('jsonwebtoken')

const { AUTH_PROOF_SECRET, JWT_SECRET } = require('../config')
const {
  ed25519Verify, leadingZeroBits, proofHmacHex, randomHex, sameHex, sha256, sha256Hex
} = require('../crypto')
const { db } = require('../db')
const { b64ok, isHash, perHour, perMinute } = require('../common')

const ANON_POW_BITS = 20
const ANON_DEFAULT_IDLE_SEC = 548 * 24 * 3600
const EMAIL_DEFAULT_IDLE_SEC = 5 * 365 * 24 * 3600
const OTP_MAX_TRACKED = 20000

function signToken(sub, deviceId) {
  return jwt.sign({ sub, deviceId }, JWT_SECRET, { expiresIn: '30d' })
}
function verifyToken(token) {
  try { return jwt.verify(token, JWT_SECRET) } catch (_) { return null }
}

async function verifyActiveDevice(token) {
  const payload = verifyToken(token)
  if (!payload) return null
  const { rows } = await db.query(
    'SELECT active_device_id FROM users WHERE email_hash=$1', [payload.sub])
  const active = rows[0]?.active_device_id
  if (!payload.deviceId) return active ? { kicked: true } : payload
  if (!active) return payload
  if (active !== payload.deviceId) return { kicked: true }
  return payload
}

function bearerToken(req) {
  return req.headers.authorization?.replace('Bearer ', '')
}

async function requireAuth(req, reply) {
  const payload = await verifyActiveDevice(bearerToken(req))
  if (!payload) return reply.code(401).send({ error: 'Brak autoryzacji' })
  if (payload.kicked) return reply.code(409).send({ error: 'device_kicked', kicked: true })
  req.auth = payload
}

function verifyAuthProof(proof, emailHash) {
  if (!AUTH_PROOF_SECRET || typeof proof !== 'string') return false
  const parts = proof.split('.')
  if (parts.length !== 3) return false
  const [h, exp, sig] = parts
  if (h !== emailHash) return false
  if (!/^[0-9]{1,15}$/.test(exp) || Number(exp) < Date.now()) return false
  return sameHex(proofHmacHex(`${h}.${exp}`), sig)
}

function signAuthProof(hash, expiresAt) {
  return `${hash}.${expiresAt}.${proofHmacHex(`${hash}.${expiresAt}`)}`
}

function issueAuthProof(hash) {
  const expiresAt = Date.now() + 900 * 1000
  return { authProof: signAuthProof(hash, expiresAt), expiresAt }
}

const anonChallenges = new Map()
const loginChallenges = new Map()
const anonPending = new Map()
setInterval(() => {
  const now = Date.now()
  for (const [k, exp] of anonChallenges) if (exp < now) anonChallenges.delete(k)
  for (const [k, v] of loginChallenges) if (v.exp < now) loginChallenges.delete(k)
  for (const [k, v] of anonPending) if (v.exp < now) anonPending.delete(k)
}, 60 * 1000)

const OTP_EXPIRY_S   = 600
const OTP_MAX_TRIES  = 5
const OTP_REUSE_S    = 120
const otpTickets = new Map()

setInterval(() => {
  const now = Math.floor(Date.now() / 1000)
  for (const [nonce, st] of otpTickets) if (st.exp < now) otpTickets.delete(nonce)
}, 60 * 1000)

function authRoutes(app) {
  app.post('/api/auth/verify', { config: perMinute(20) }, async (req, reply) => {
    if (!AUTH_PROOF_SECRET) return reply.code(503).send({ success: false, error: 'Weryfikacja chwilowo niedostępna' })

    const body   = req.body || {}
    const email  = String(body.email || '').trim().toLowerCase()
    const code   = String(body.code || '').trim()
    const ticket = String(body.ticket || '').trim()
    if (!email || !code) return reply.send({ success: false, error: 'Brak danych' })

    const m = /^([0-9a-f]{16,64})\.([0-9]{1,12})\.([0-9a-f]{64})$/.exec(ticket)
    if (!m) return reply.send({ success: false, error: 'Nieprawidłowe żądanie. Wyślij kod ponownie.' })
    const [, nonce, expStr, mac] = m
    const exp = Number(expStr)
    const now = Math.floor(Date.now() / 1000)
    if (now > exp) return reply.send({ success: false, error: 'Kod wygasł. Wyślij nowy.' })
    if (exp > now + OTP_EXPIRY_S + 60) {
      return reply.send({ success: false, error: 'Nieprawidłowe żądanie. Wyślij kod ponownie.' })
    }

    let st = otpTickets.get(nonce)
    if (st && st.attempts >= OTP_MAX_TRIES) {
      return reply.send({ success: false, error: 'Za dużo błędnych prób. Wyślij nowy kod.' })
    }
    if (st && st.usedAt && now - st.usedAt > OTP_REUSE_S) {
      return reply.send({ success: false, error: 'Ten kod został już użyty. Wyślij nowy.' })
    }
    if (!st) {
      if (otpTickets.size >= OTP_MAX_TRACKED) {
        return reply.code(503).send({ success: false, error: 'Spróbuj za chwilę' })
      }
      st = { attempts: 0, usedAt: 0, exp }
      otpTickets.set(nonce, st)
    }

    const emailHash = sha256Hex(email)
    const ok = /^[0-9]{4,10}$/.test(code) && sameHex(proofHmacHex(`otp|${emailHash}|${nonce}|${exp}|${code}`), mac)
    if (!ok) {
      st.attempts++
      const triesLeft = Math.max(0, OTP_MAX_TRIES - st.attempts)
      return reply.send({ success: false, error: `Nieprawidłowy kod. Pozostało prób: ${triesLeft}` })
    }

    if (!st.usedAt) st.usedAt = now
    const expiresAt = (now + 900) * 1000
    return reply.send({
      success: true,
      emailHash,
      authProof: signAuthProof(emailHash, expiresAt),
      expiresAt
    })
  })

  app.post('/api/auth/transfer-proof', { config: perMinute(5) }, async (req, reply) => {
    if (!AUTH_PROOF_SECRET) return reply.code(503).send({ error: 'Przenoszenie konta chwilowo niedostępne' })
    const auth = bearerToken(req)
    const payload = auth ? await verifyActiveDevice(auth) : null
    if (!payload) return reply.code(401).send({ error: 'Brak autoryzacji' })
    if (payload.kicked) return reply.code(409).send({ error: 'device_kicked' })
    const emailHash = String(payload.sub || '')
    if (!isHash(emailHash)) return reply.code(400).send({ error: 'Nieprawidłowe konto' })
    return issueAuthProof(emailHash)
  })

  app.post('/api/anon/challenge', { config: perMinute(20) }, async (req, reply) => {
    if (!AUTH_PROOF_SECRET) return reply.code(503).send({ error: 'Chwilowo niedostępne' })
    if (anonChallenges.size > 20000) anonChallenges.clear()
    const challenge = randomHex(16)
    anonChallenges.set(challenge, Date.now() + 10 * 60 * 1000)
    return { challenge, bits: ANON_POW_BITS }
  })

  app.post('/api/anon/register', { config: perHour(5) }, async (req, reply) => {
    if (!AUTH_PROOF_SECRET) return reply.code(503).send({ error: 'Chwilowo niedostępne' })
    const { accountHash, loginKey, challenge, nonce } = req.body || {}
    const hash = String(accountHash || '')
    if (!isHash(hash)) return reply.code(400).send({ error: 'Nieprawidłowe dane' })
    if (!b64ok(loginKey, 60) || Buffer.from(String(loginKey), 'base64').length !== 32) {
      return reply.code(400).send({ error: 'Nieprawidłowe dane' })
    }
    const exp = anonChallenges.get(String(challenge || ''))
    anonChallenges.delete(String(challenge || ''))
    if (!exp || exp < Date.now()) return reply.code(400).send({ error: 'Wyzwanie wygasło', code: 'challenge_expired' })
    const n = String(nonce ?? '')
    if (!/^[0-9]{1,16}$/.test(n)) return reply.code(400).send({ error: 'Nieprawidłowe dane' })
    const digest = sha256(`${challenge}:${n}`)
    if (leadingZeroBits(digest) < ANON_POW_BITS) {
      return reply.code(400).send({ error: 'Nieprawidłowy dowód', code: 'bad_pow' })
    }
    const { rows } = await db.query('SELECT 1 FROM users WHERE email_hash=$1', [hash])
    if (rows.length) return reply.code(409).send({ error: 'Konto już istnieje', code: 'exists' })
    anonPending.set(hash, { loginKey: String(loginKey), exp: Date.now() + 900 * 1000 })
    return issueAuthProof(hash)
  })

  app.post('/api/anon/login-challenge', { config: perMinute(20) }, async (req, reply) => {
    const hash = String(req.body?.accountHash || '')
    if (!isHash(hash)) return reply.code(400).send({ error: 'Nieprawidłowe dane' })
    if (loginChallenges.size > 20000) loginChallenges.clear()
    const challenge = randomHex(16)
    loginChallenges.set(challenge, { hash, exp: Date.now() + 5 * 60 * 1000 })
    return { challenge }
  })

  app.post('/api/anon/login', { config: perMinute(10) }, async (req, reply) => {
    if (!AUTH_PROOF_SECRET) return reply.code(503).send({ error: 'Chwilowo niedostępne' })
    const { accountHash, challenge, signature } = req.body || {}
    const hash = String(accountHash || '')
    const ch = loginChallenges.get(String(challenge || ''))
    loginChallenges.delete(String(challenge || ''))
    const deny = () => reply.code(401).send({ error: 'Nie udało się zalogować', code: 'login_failed' })
    if (!ch || ch.exp < Date.now() || ch.hash !== hash) return deny()
    const { rows } = await db.query(
      "SELECT login_key FROM users WHERE email_hash=$1 AND account_kind='anon'", [hash])
    if (!rows.length || !rows[0].login_key) return deny()
    if (!ed25519Verify(rows[0].login_key, `SinusChat login v1|${hash}|${challenge}`, signature)) return deny()
    return issueAuthProof(hash)
  })
}

module.exports = {
  authRoutes, requireAuth, bearerToken, verifyToken, verifyActiveDevice, signToken,
  verifyAuthProof, anonPending, ANON_DEFAULT_IDLE_SEC, EMAIL_DEFAULT_IDLE_SEC
}
