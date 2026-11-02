// SinusChat — serwer. Copyright © 2026 Sinusoide Technology. SPDX-License-Identifier: AGPL-3.0-only

'use strict'

const { TURN_HOST } = require('../config')
const { turnCredential } = require('../crypto')
const {
  canUseConversation, connections, DIRECT_TARGET_LIMIT, dropConnection, groupAllows, isBlockedBy,
  isGroupId, isParticipant, lookupAllowed, memberHashes, otherMemberHashes, otherParty, sendJson,
  sendToAll, sendToUser, userExists
} = require('../common')
const { requireAuth } = require('./auth')
const { wakeUser } = require('./push')

const ENDED_CALL_TTL_MS = 120_000
const CALL_OFFER_TTL_MS = 40_000
const CALL_ACK_TIMEOUT_MS = 4_000
const GCALL_MEMBER_TTL_MS = 60_000
const GCALL_SIGNAL_LIMIT = 200
const GCALL_SIGNAL_MAX_CHARS = 96 * 1024

const pendingCallOffers = new Map()
const endedCalls = new Map()
setInterval(() => {
  const cut = Date.now() - ENDED_CALL_TTL_MS
  for (const [k, ts] of endedCalls) if (ts < cut) endedCalls.delete(k)
}, 60_000).unref?.()
const pendingGcallRings = new Map()

const groupCalls = new Map()

function gcallState(gid) {
  const c = groupCalls.get(gid)
  if (!c) return { type: 'gcall_state', conversationId: gid, active: false, now: Date.now() }
  return {
    type: 'gcall_state', conversationId: gid, active: true, kind: c.kind,
    startedBy: c.startedBy, startedAt: c.startedAt, members: [...c.members.keys()], now: Date.now()
  }
}

async function gcallBroadcast(gid) {
  const state = gcallState(gid)
  try {
    sendToAll(await memberHashes(gid), state)
  } catch (_) {}
}

async function gcallSendActive(userHash) {
  for (const gid of groupCalls.keys()) {
    if (await isParticipant(gid, userHash)) sendToUser(userHash, gcallState(gid))
  }
}

setInterval(() => {
  const cutoff = Date.now() - GCALL_MEMBER_TTL_MS
  for (const [gid, c] of groupCalls) {
    let changed = false
    for (const [hash, seen] of c.members) {
      if (seen < cutoff) { c.members.delete(hash); changed = true }
    }
    if (c.members.size === 0) { groupCalls.delete(gid); changed = true }
    if (changed) gcallBroadcast(gid)
  }
}, 15_000)
setInterval(() => {
  const cutoff = Date.now() - CALL_OFFER_TTL_MS
  for (const [h, o] of pendingCallOffers) if (o.ts < cutoff) pendingCallOffers.delete(h)
  for (const [k, t] of pendingGcallRings) if (t < cutoff) pendingGcallRings.delete(k)
}, 10_000)

function wakeForCall(userHash) {
  wakeUser(userHash, 'call', { title: 'Połączenie przychodzące' }).catch(() => {})
}

function isOfferFrom(offer, conversationId, callerHash) {
  return !!offer && offer.conversationId === conversationId && offer.fromHash === callerHash
}

function rememberCallEnd(type, conversationId, userHash) {
  const key = `${conversationId}|${userHash}`
  if (type === 'call_end' || type === 'call_reject') endedCalls.set(key, Date.now())
  else if (type === 'call_offer') endedCalls.delete(key)
}

function answeredEndedCall(conversationId, userHash) {
  const caller = otherParty(conversationId, userHash)
  const ended = endedCalls.get(`${conversationId}|${caller}`)
  if (!ended || Date.now() - ended >= ENDED_CALL_TTL_MS) return false
  sendToUser(userHash, { type: 'call_end', conversationId, fromHash: caller, senderHash: caller, reason: 'gone' })
  return true
}

function watchOfferAck(socket, recipient, conversationId, callerHash) {
  setTimeout(() => {
    if (!isOfferFrom(pendingCallOffers.get(recipient), conversationId, callerHash)) return
    dropConnection(recipient, socket)
    wakeForCall(recipient)
  }, CALL_ACK_TIMEOUT_MS)
}

function trackOffer(msg, callerHash, recipient, socket, live) {
  pendingCallOffers.set(recipient, { ...msg, fromHash: callerHash, ts: Date.now() })
  if (!live) wakeForCall(recipient)
  else if (socket && socket.callAckSupported) watchOfferAck(socket, recipient, msg.conversationId, callerHash)
  else pendingCallOffers.delete(recipient)
}

async function relayToRecipient(msg, callerHash, recipient, isGroup) {
  const { type, conversationId } = msg
  const isOffer = type === 'call_offer'

  if (!isGroup && isOffer && !lookupAllowed('d', callerHash, recipient, DIRECT_TARGET_LIMIT)) {
    sendToUser(callerHash, { type: 'call_reject', conversationId, reason: 'limit' })
    return
  }
  if (!isGroup && !(await userExists(recipient))) {
    if (isOffer) sendToUser(callerHash, { type: 'call_reject', conversationId, reason: 'account_deleted' })
    return
  }
  if (await isBlockedBy(recipient, callerHash)) return

  if ((type === 'call_end' || type === 'call_reject') &&
      isOfferFrom(pendingCallOffers.get(recipient), conversationId, callerHash)) {
    pendingCallOffers.delete(recipient)
  }

  const socket = connections.get(recipient)
  const live = sendToUser(recipient, { ...msg, fromHash: callerHash, senderHash: callerHash })
  if (type === 'call_end') {
    sendToUser(recipient, {
      type: 'call_cancel', kind: 'call_end', conversationId, fromHash: callerHash, senderHash: callerHash
    })
  }
  if (isOffer) trackOffer(msg, callerHash, recipient, socket, live)
}

async function handleCall({ userHash }, msg) {
  const { type, conversationId } = msg
  if (!conversationId) return
  try {
    if (!(await canUseConversation(conversationId, userHash))) return
    const isGroup = isGroupId(conversationId)

    if (isGroup && type === 'call_offer' && !(await groupAllows(conversationId, userHash, 'callGroup'))) {
      sendToUser(userHash, { type: 'call_reject', conversationId, reason: 'group_call_forbidden' })
      return
    }
    if (!isGroup) {
      rememberCallEnd(type, conversationId, userHash)
      if (type === 'call_answer' && answeredEndedCall(conversationId, userHash)) return
    }

    const recipients = isGroup
      ? await otherMemberHashes(conversationId, userHash)
      : [otherParty(conversationId, userHash)]
    for (const recipient of recipients) await relayToRecipient(msg, userHash, recipient, isGroup)
  } catch (_) {}
}

const ringKey = (userHash, groupId) => userHash + '|' + groupId

function wakeForGroupCall(userHash) {
  wakeUser(userHash, 'call', { title: 'Rozmowa grupowa' }).catch(() => {})
}

function watchRingAck(socket, member, groupId, call) {
  const key = ringKey(member, groupId)
  pendingGcallRings.set(key, Date.now())
  setTimeout(() => {
    if (!pendingGcallRings.delete(key)) return
    if (groupCalls.get(groupId) !== call || call.members.has(member)) return
    dropConnection(member, socket)
    wakeForGroupCall(member)
  }, CALL_ACK_TIMEOUT_MS)
}

async function ringMembers(groupId, call, callerHash) {
  for (const member of await otherMemberHashes(groupId, callerHash)) {
    if (await isBlockedBy(member, callerHash)) continue
    const socket = connections.get(member)
    if (!socket) wakeForGroupCall(member)
    else if (socket.gcallAckSupported) watchRingAck(socket, member, groupId, call)
  }
}

async function startCall({ socket, userHash }, groupId, kind) {
  if (!(await groupAllows(groupId, userHash, 'callGroup'))) {
    sendJson(socket, { type: 'gcall_error', conversationId: groupId, reason: 'group_call_forbidden' })
    return
  }
  const call = {
    kind: kind === 'video' ? 'video' : 'audio',
    startedBy: userHash,
    startedAt: Date.now(),
    members: new Map([[userHash, Date.now()]])
  }
  groupCalls.set(groupId, call)
  await gcallBroadcast(groupId)
  try {
    await ringMembers(groupId, call, userHash)
  } catch (_) {}
}

function relaySignal(call, groupId, userHash, msg) {
  const to = String(msg.to || '')
  if (!call || !call.members.has(userHash) || !call.members.has(to) || to === userHash) return
  if (typeof msg.payload !== 'string' || msg.payload.length > GCALL_SIGNAL_MAX_CHARS) return
  call.members.set(userHash, Date.now())
  sendToUser(to, { type: 'gcall_signal', conversationId: groupId, from: userHash, payload: msg.payload })
}

async function handleGroupCall(session, msg) {
  const { socket, userHash } = session
  const groupId = String(msg.conversationId || '')
  if (!isGroupId(groupId)) return
  const call = groupCalls.get(groupId)

  if (msg.type === 'gcall_ack') {
    pendingGcallRings.delete(ringKey(userHash, groupId))
    return
  }
  if (msg.type === 'gcall_ping') {
    if (call && call.members.has(userHash)) call.members.set(userHash, Date.now())
    else if (await isParticipant(groupId, userHash)) sendJson(socket, gcallState(groupId))
    return
  }
  if (msg.type === 'gcall_signal') {
    relaySignal(call, groupId, userHash, msg)
    return
  }

  if (!(await isParticipant(groupId, userHash))) return

  if (msg.type === 'gcall_query') {
    sendJson(socket, gcallState(groupId))
  } else if (msg.type === 'gcall_leave') {
    if (!call || !call.members.delete(userHash)) return
    if (call.members.size === 0) groupCalls.delete(groupId)
    await gcallBroadcast(groupId)
  } else if (msg.type === 'gcall_start' || msg.type === 'gcall_join') {
    if (call) {
      call.members.set(userHash, Date.now())
      await gcallBroadcast(groupId)
    } else if (msg.type === 'gcall_join') {
      sendJson(socket, gcallState(groupId))
    } else {
      await startCall(session, groupId, msg.kind)
    }
  }
}

function callRoutes(app) {
  app.post('/api/call/reject', { preHandler: requireAuth }, async (req, reply) => {
    const myHash = req.auth.sub
    const { conversationId } = req.body || {}
    if (!conversationId) return reply.code(400).send({ error: 'Brak conversationId' })
    if (!(await canUseConversation(conversationId, myHash))) {
      return reply.code(403).send({ error: 'Brak dostępu do rozmowy' })
    }

    sendToAll(await otherMemberHashes(conversationId, myHash), { type: 'call_reject', conversationId })
    return { ok: true }
  })

  app.get('/api/turn-credentials', { preHandler: requireAuth }, async (req) => {
    const ttl = 3600
    const ts = Math.floor(Date.now() / 1000) + ttl
    const username = `${ts}:${req.auth.sub}`
    return {
      urls: [
        `stun:${TURN_HOST}:3478`,
        `turn:${TURN_HOST}:3478?transport=udp`,
        `turn:${TURN_HOST}:3478?transport=tcp`,
        `turns:${TURN_HOST}:5349?transport=tcp`
      ],
      username,
      credential: turnCredential(username),
      ttl
    }
  })
}

module.exports = {
  callRoutes, handleCall, handleGroupCall, gcallSendActive, pendingCallOffers, GCALL_SIGNAL_LIMIT,
  CALL_OFFER_TTL_MS
}
