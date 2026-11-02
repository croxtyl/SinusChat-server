// SinusChat — serwer. Copyright © 2026 Sinusoide Technology. SPDX-License-Identifier: AGPL-3.0-only

'use strict'

const { db } = require('../db')
const {
  allSockets, canonicalPair, canUseConversation, clientIp, connections, isBlockedBy, isGroupId,
  isParticipant, kickSocket, sendJson, sendToUser, WS_OPEN
} = require('../common')
const { verifyToken } = require('./auth')
const {
  CALL_OFFER_TTL_MS, GCALL_SIGNAL_LIMIT, gcallSendActive, handleCall, handleGroupCall,
  pendingCallOffers
} = require('./calls')
const { relayDirectAck } = require('./messages')
const { loadNtfyTopic } = require('./push')

const TYPING_MAX_RECIPIENTS = 20
const WS_MSG_LIMIT = 40
const WS_MSG_WINDOW_MS = 10_000
const WS_MSG_MAX_CHARS = 256 * 1024
const WS_CONN_PER_IP = 10
const CALL_SIGNALS = new Set([
  'call_offer', 'call_answer', 'call_ice', 'call_reject', 'call_end', 'call_reoffer', 'call_reanswer', 'call_screen'
])
const GCALL_KEEPALIVES = new Set(['gcall_signal', 'gcall_ping'])

async function handleAuth(session, msg) {
  const { socket } = session
  const payload = verifyToken(msg.token)
  if (!payload) { sendJson(socket, { type: 'auth_error' }); return }
  const userHash = session.userHash = payload.sub

  try {
    const { rows } = await db.query(
      'SELECT active_device_id FROM users WHERE email_hash=$1', [userHash])
    const active = rows[0]?.active_device_id
    if (active && active !== payload.deviceId) {
      sendJson(socket, { type: 'device_kicked' })
      try { socket.close() } catch (_) {}
      return
    }
  } catch (_) {}
  socket.deviceId = payload.deviceId || null

  const prev = connections.get(userHash)
  if (prev && prev !== socket && prev.readyState === WS_OPEN) kickSocket(prev)

  connections.set(userHash, socket)
  const caps = Array.isArray(msg.caps) ? msg.caps : []
  socket.callAckSupported = caps.includes('call_ack')
  socket.gcallAckSupported = caps.includes('gcall_ack')
  if (caps.includes('call_e2e')) {
    db.query('UPDATE users SET call_e2e=true WHERE email_hash=$1 AND call_e2e IS NOT TRUE', [userHash])
      .catch(() => {})
  }
  sendJson(socket, { type: 'auth_ok', hash: userHash, userHash })
  loadNtfyTopic(userHash)

  gcallSendActive(userHash).catch(() => {})

  const pending = pendingCallOffers.get(userHash)
  if (pending) {
    if (!socket.callAckSupported) pendingCallOffers.delete(userHash)
    if (Date.now() - pending.ts < CALL_OFFER_TTL_MS) {
      const { ts, ...offer } = pending
      sendJson(socket, offer)
    }
  }
}

async function canReceiveTyping(conversationId, senderHash, recipient) {
  if (!isGroupId(conversationId) && conversationId === canonicalPair(senderHash, recipient)) return true
  return isParticipant(conversationId, recipient)
}

async function notifyMembers(conversationId, senderHash, signal) {
  const { rows } = await db.query(
    `SELECT user_hash FROM conversation_participants
      WHERE conversation_id=$1 AND user_hash!=$2 LIMIT ${TYPING_MAX_RECIPIENTS}`,
    [conversationId, senderHash]
  )
  for (const { user_hash } of rows) {
    if (await isBlockedBy(user_hash, senderHash)) continue
    sendToUser(user_hash, signal)
  }
}

async function handleTyping({ userHash }, msg) {
  const { type, conversationId, recipientHash } = msg
  if (!(await canUseConversation(conversationId, userHash))) return
  const signal = { type, conversationId, senderHash: userHash }

  if (recipientHash) {
    if (!(await canReceiveTyping(conversationId, userHash, String(recipientHash)))) return
    if (await isBlockedBy(recipientHash, userHash)) return
    sendToUser(recipientHash, signal)
    return
  }
  try {
    await notifyMembers(conversationId, userHash, signal)
  } catch (_) {}
}

const wsConnByIp = new Map()

function ackCallOffer(userHash, msg) {
  const offer = pendingCallOffers.get(userHash)
  if (offer && offer.conversationId === msg.conversationId) pendingCallOffers.delete(userHash)
}

async function relayAck(userHash, { conversationId, deliveredUpTo, readUpTo }) {
  if (conversationId && !isGroupId(conversationId) && await canUseConversation(conversationId, userHash)) {
    await relayDirectAck(userHash, conversationId, deliveredUpTo, readUpTo)
  }
}

async function dispatch(session, msg) {
  if (msg.type === 'auth') return handleAuth(session, msg)
  if (msg.type === 'call_offer_ack') return ackCallOffer(session.userHash, msg)
  if (!session.userHash) return

  if (msg.type === 'ping') return sendJson(session.socket, { type: 'pong' })
  if (typeof msg.type === 'string' && msg.type.startsWith('gcall_')) return handleGroupCall(session, msg)
  if (CALL_SIGNALS.has(msg.type)) return handleCall(session, msg)
  if (msg.type === 'typing' || msg.type === 'typing_stop') return handleTyping(session, msg)
  if (msg.type === 'ack') return relayAck(session.userHash, msg)
}

function createFloodGuard() {
  let messages = 0
  let signals = 0
  let windowStart = Date.now()

  return {
    tick() {
      const now = Date.now()
      if (now - windowStart <= WS_MSG_WINDOW_MS) return
      windowStart = now
      messages = 0
      signals = 0
    },
    allows(msg) {
      if (msg && GCALL_KEEPALIVES.has(msg.type)) return ++signals <= GCALL_SIGNAL_LIMIT
      return ++messages <= WS_MSG_LIMIT
    }
  }
}

function releaseIpSlot(ip) {
  const remaining = (wsConnByIp.get(ip) || 1) - 1
  if (remaining <= 0) wsConnByIp.delete(ip)
  else wsConnByIp.set(ip, remaining)
}

async function wsRoutes(app) {
  app.get('/ws', { websocket: true }, (socket, req) => {
    const ip = clientIp(req) || 'unknown'
    const connectionsFromIp = wsConnByIp.get(ip) || 0
    if (connectionsFromIp >= WS_CONN_PER_IP) {
      try { socket.close(1013, 'Za dużo połączeń') } catch (_) {}
      return
    }
    wsConnByIp.set(ip, connectionsFromIp + 1)

    const session = { socket, userHash: null }
    const floodGuard = createFloodGuard()

    socket.on('message', async (raw) => {
      try {
        floodGuard.tick()
        const text = (raw && raw.data !== undefined) ? raw.data.toString() : raw.toString()
        if (text.length > WS_MSG_MAX_CHARS) return
        const msg = JSON.parse(text)
        if (floodGuard.allows(msg)) await dispatch(session, msg)
      } catch (_) {}
    })

    socket.heartbeatAlive = true
    socket.on('pong', () => { socket.heartbeatAlive = true })
    allSockets.add(socket)

    socket.on('close', () => {
      allSockets.delete(socket)
      if (session.userHash && connections.get(session.userHash) === socket) connections.delete(session.userHash)
      releaseIpSlot(ip)
    })
  })
}

module.exports = { wsRoutes }
