// SinusChat — serwer. Copyright © 2026 Sinusoide Technology. SPDX-License-Identifier: AGPL-3.0-only

'use strict'

const { accessKeyMatches } = require('./crypto')
const { db } = require('./db')

const HOUR_MS = 60 * 60 * 1000
const DAY_MS = 24 * HOUR_MS
const SENDER_BUDGET_BYTES = 200 * 1024 * 1024
const SEALED_BUDGET_BYTES = 50 * 1024 * 1024
const HIDDEN_LOOKUP_LIMIT = 300
const DIRECT_TARGET_LIMIT = 500
const LOOKUP_WINDOW_MS = DAY_MS
const SEALED_FLOOD_LIMIT = 600
const SEALED_WINDOW_MS = 60_000
const SEARCH_LIMIT = 20
const SEARCH_WINDOW_MS = 10 * 60_000
const HASH_RE = /^[a-f0-9]{64}$/
const B64_RE = /^[A-Za-z0-9+/]+={0,2}$/
const MAX_KEY_ID = 0xFFFFFF
const WS_OPEN = 1

const MESSAGE_MAX_BYTES   = 512 * 1024
const VOICE_BUDGET_BYTES  = 100 * 1024 * 1024
const SEALED_MAX_B64      = 700 * 1024

const queueBudgets = new Map()
const lookupBudgets = new Map()
const sealedPerRecipient = new Map()
const searchHits = new Map()

const perMinute = (max) => ({ rateLimit: { max, timeWindow: '1 minute' } })
const perHour = (max) => ({ rateLimit: { max, timeWindow: '1 hour' } })

function clientIp(req) {
  return String(req.headers['x-real-ip'] || req.ip || '').trim()
}

function spendBudget(key, bytes, limit) {
  const now = Date.now()
  const budget = queueBudgets.get(key)
  if (!budget || now - budget.start > HOUR_MS) {
    queueBudgets.set(key, { start: now, spent: bytes })
    return bytes <= limit
  }
  budget.spent += bytes
  return budget.spent <= limit
}

function lookupAllowed(kind, requester, target, limit) {
  if (!requester || !target || requester === target) return true
  const key = kind + ':' + requester
  const now = Date.now()
  let budget = lookupBudgets.get(key)
  if (!budget || now - budget.start > LOOKUP_WINDOW_MS) {
    budget = { start: now, seen: new Set() }
    lookupBudgets.set(key, budget)
  }
  if (budget.seen.has(target)) return true
  if (budget.seen.size >= limit) return false
  budget.seen.add(target)
  return true
}

function sealedFlood(to) {
  const now = Date.now()
  const window = sealedPerRecipient.get(to)
  if (!window || now - window.start > SEALED_WINDOW_MS) {
    sealedPerRecipient.set(to, { start: now, count: 1 })
    return false
  }
  return ++window.count > SEALED_FLOOD_LIMIT
}

function searchAllowed(userHash) {
  const now = Date.now()
  const cutoff = now - SEARCH_WINDOW_MS
  const hits = (searchHits.get(userHash) || []).filter(t => t > cutoff)
  const allowed = hits.length < SEARCH_LIMIT
  if (allowed) hits.push(now)
  searchHits.set(userHash, hits)
  return allowed
}

function dropExpired(map, windowMs) {
  const cutoff = Date.now() - windowMs
  for (const [key, entry] of map) if (entry.start < cutoff) map.delete(key)
}

setInterval(() => dropExpired(queueBudgets, HOUR_MS), 10 * 60_000).unref()
setInterval(() => dropExpired(lookupBudgets, LOOKUP_WINDOW_MS), 10 * 60_000).unref()
setInterval(() => dropExpired(sealedPerRecipient, SEALED_WINDOW_MS), 5 * 60_000).unref()

setInterval(() => {
  const cutoff = Date.now() - SEARCH_WINDOW_MS
  for (const [hash, hits] of searchHits) {
    const fresh = hits.filter(t => t > cutoff)
    if (fresh.length) searchHits.set(hash, fresh)
    else searchHits.delete(hash)
  }
}, SEARCH_WINDOW_MS)

const isHash = (value) => HASH_RE.test(value)

function b64ok(s, max) {
  return typeof s === 'string' && s.length > 0 && s.length <= max && B64_RE.test(s)
}

function keyIdOk(id) {
  return Number.isInteger(id) && id > 0 && id < MAX_KEY_ID
}

function signedKeyOk(k, maxPub) {
  return !!k && keyIdOk(k.id) && b64ok(k.pub, maxPub) && b64ok(k.sig, 200)
}

function clip(v, max) {
  if (v === undefined || v === null) return null
  const s = String(v).replace(/\u0000/g, '').trim()
  return s ? s.slice(0, max) : null
}

const connections = new Map()
const allSockets = new Set()

setInterval(() => {
  for (const ws of allSockets) {
    if (ws.heartbeatAlive === false) {
      try { ws.terminate() } catch (_) {}
      continue
    }
    ws.heartbeatAlive = false
    try { ws.ping() } catch (_) {}
  }
}, 30_000)

function sendJson(socket, data) {
  socket.send(JSON.stringify(data))
}

function sendToUser(userHash, data) {
  const ws = connections.get(userHash)
  if (!ws || ws.readyState !== WS_OPEN) return false
  sendJson(ws, data)
  return true
}

function sendToAll(userHashes, data) {
  for (const hash of userHashes) sendToUser(hash, data)
}

function kickSocket(socket) {
  try { sendJson(socket, { type: 'device_kicked' }) } catch (_) {}
  try { socket.close() } catch (_) {}
}

function closeConnection(userHash) {
  const ws = connections.get(userHash)
  if (!ws) return
  try { ws.close() } catch (_) {}
}

function dropConnection(userHash, socket) {
  if (connections.get(userHash) !== socket) return
  connections.delete(userHash)
  try { socket.terminate() } catch (_) {}
}

const isGroupId = (conversationId) => String(conversationId).startsWith('g_')

function otherParty(conversationId, userHash) {
  const [a, b] = String(conversationId).split('_')
  return a === userHash ? b : a
}

function canonicalPair(a, b) {
  return a < b ? `${a}_${b}` : `${b}_${a}`
}

function directMember(conversationId, userHash) {
  const parts = String(conversationId || '').split('_')
  return parts.length === 2 && canonicalPair(parts[0], parts[1]) === conversationId &&
    (parts[0] === userHash || parts[1] === userHash)
}

async function membership(conversationId, userHash) {
  const { rows } = await db.query(
    'SELECT is_admin FROM conversation_participants WHERE conversation_id=$1 AND user_hash=$2',
    [conversationId, userHash]
  )
  return rows[0] || null
}

async function isParticipant(conversationId, userHash) {
  if (!conversationId || !userHash) return false
  try {
    return !!(await membership(conversationId, userHash))
  } catch (_) { return false }
}

async function memberHashes(conversationId) {
  const { rows } = await db.query(
    'SELECT user_hash FROM conversation_participants WHERE conversation_id=$1', [conversationId])
  return rows.map(r => r.user_hash)
}

async function otherMemberHashes(conversationId, userHash) {
  const { rows } = await db.query(
    'SELECT user_hash FROM conversation_participants WHERE conversation_id=$1 AND user_hash!=$2',
    [conversationId, userHash]
  )
  return rows.map(r => r.user_hash)
}

async function memberCount(conversationId) {
  const { rows } = await db.query(
    'SELECT COUNT(*)::int AS n FROM conversation_participants WHERE conversation_id=$1', [conversationId])
  return rows[0]?.n || 0
}

async function contactsOf(userHash) {
  const { rows } = await db.query(
    `SELECT DISTINCT cp2.user_hash FROM conversation_participants cp1
       JOIN conversation_participants cp2 ON cp2.conversation_id = cp1.conversation_id
      WHERE cp1.user_hash = $1 AND cp2.user_hash <> $1`, [userHash])
  return rows.map(r => r.user_hash)
}

async function canUseConversation(conversationId, userHash) {
  if (!conversationId || !userHash) return false
  if (isGroupId(conversationId)) return isParticipant(conversationId, userHash)
  return directMember(conversationId, userHash) || isParticipant(conversationId, userHash)
}

async function isBlockedBy(blockerHash, blockedHash) {
  if (!blockerHash || !blockedHash) return false
  try {
    const { rows } = await db.query(
      'SELECT 1 FROM blocked_users WHERE blocker_hash=$1 AND blocked_hash=$2 LIMIT 1',
      [blockerHash, blockedHash]
    )
    return rows.length > 0
  } catch (_) { return false }
}

async function isGroupBanned(groupId, userHash) {
  try {
    const { rows } = await db.query(
      'SELECT 1 FROM group_bans WHERE group_id=$1 AND user_hash=$2 LIMIT 1', [groupId, userHash])
    return rows.length > 0
  } catch (_) { return false }
}

async function groupAllows(groupId, userHash, key) {
  try {
    const { rows } = await db.query(
      `SELECT cp.is_admin, g.perms
         FROM conversation_participants cp
         JOIN groups g ON g.id = cp.conversation_id
        WHERE cp.conversation_id = $1 AND cp.user_hash = $2
        LIMIT 1`,
      [groupId, userHash]
    )
    if (!rows.length) return false
    if (rows[0].is_admin) return true
    let perms = rows[0].perms || {}
    if (typeof perms === 'string') { try { perms = JSON.parse(perms) } catch (_) { perms = {} } }
    return perms[key] !== false
  } catch (_) { return false }
}

async function sharesGroup(a, b) {
  if (!a || !b) return false
  try {
    const { rows } = await db.query(
      `SELECT 1 FROM conversation_participants cp1
       JOIN conversation_participants cp2 ON cp1.conversation_id = cp2.conversation_id
       WHERE cp1.user_hash = $1 AND cp2.user_hash = $2 AND cp1.conversation_id LIKE 'g!_%' ESCAPE '!' LIMIT 1`,
      [a, b]
    )
    return rows.length > 0
  } catch (_) { return false }
}

async function newChatsBlocked(targetHash) {
  try {
    const { rows } = await db.query('SELECT block_new, ua_hash FROM users WHERE email_hash=$1', [targetHash])
    return rows[0]?.block_new === true ? { uaHash: rows[0].ua_hash } : null
  } catch (_) { return null }
}

async function knownContact(block, targetHash, requester, akB64) {
  if (!block) return true
  if (accessKeyMatches(block.uaHash, akB64)) return true
  return sharesGroup(requester, targetHash)
}

async function userExists(hash) {
  try {
    const { rows } = await db.query('SELECT 1 FROM users WHERE email_hash=$1', [String(hash)])
    return rows.length > 0
  } catch (_) { return true }
}

module.exports = {
  HOUR_MS, DAY_MS, MESSAGE_MAX_BYTES, SENDER_BUDGET_BYTES, SEALED_BUDGET_BYTES, VOICE_BUDGET_BYTES,
  SEALED_MAX_B64, HIDDEN_LOOKUP_LIMIT, DIRECT_TARGET_LIMIT, perMinute, perHour, clientIp,
  spendBudget, lookupAllowed, sealedFlood, searchAllowed, isHash, b64ok, keyIdOk, signedKeyOk,
  clip, WS_OPEN, connections, allSockets, sendJson, sendToUser, sendToAll, kickSocket,
  closeConnection, dropConnection, isGroupId, otherParty, canonicalPair, directMember, membership,
  isParticipant, memberHashes, otherMemberHashes, memberCount, contactsOf, canUseConversation,
  isBlockedBy, isGroupBanned, groupAllows, newChatsBlocked, knownContact, userExists
}
