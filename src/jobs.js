// SinusChat — serwer. Copyright © 2026 Sinusoide Technology. SPDX-License-Identifier: AGPL-3.0-only

'use strict'

const { db } = require('./db')
const { DAY_MS, HOUR_MS } = require('./common')
const { getFreeDiskGB, purgeOldVoice } = require('./routes/media')
const { purgeOldMessages } = require('./routes/messages')
const { purgeOldReports } = require('./routes/reports')
const { purgeInactiveAccounts, purgeScheduledAccounts } = require('./routes/users')

async function purgeOldInvites() {
  try {
    await db.query(
      `DELETE FROM contact_invites
        WHERE revoked = true
           OR (kind = 'once' AND used_at IS NOT NULL AND used_at < $1)
           OR (kind = 'once' AND expires_at IS NOT NULL AND expires_at < $1)`,
      [Date.now() - DAY_MS])
  } catch (_) {}
}

async function cleanupMessagesAndGroups() {
  try {
    const cutoff30d = Date.now() - 30 * DAY_MS
    const { rowCount } = await db.query(
      'DELETE FROM messages WHERE delivered_at IS NULL AND created_at < $1::bigint',
      [cutoff30d]
    )
    if (rowCount > 0) console.log('[cleanup] Usunięto', rowCount, 'nieodebranych wiadomości')

    await db.query(
      'DELETE FROM messages WHERE delivered_at IS NOT NULL AND delivered_at < $1::bigint',
      [Date.now() - HOUR_MS]
    )

    const groupCutoffDay = Math.floor(Date.now() / DAY_MS) - 548
    await db.query(`
      DELETE FROM conversation_participants cp
      USING groups g
      WHERE g.id = cp.conversation_id
        AND g.last_active_day IS NOT NULL
        AND g.last_active_day < $1::integer
    `, [groupCutoffDay])
  } catch (e) { console.error('[cleanup]', e.message) }
}

function checkDiskSpace() {
  const freeGB = getFreeDiskGB()
  if (freeGB < 10) console.warn(`[DISK WARNING] Wolne miejsce: ${freeGB}GB!`)
  if (freeGB < 5)  console.error(`[DISK CRITICAL] Tylko ${freeGB}GB wolnego!`)
}

function startJobs(schemaReady) {
  schemaReady.then(purgeOldMessages).then(purgeOldVoice)
    .then(() => setTimeout(purgeScheduledAccounts, 30_000))
  setTimeout(purgeOldReports, 60 * 1000)

  setInterval(purgeOldMessages, HOUR_MS)
  setInterval(purgeOldVoice, HOUR_MS)
  setInterval(purgeScheduledAccounts, HOUR_MS)
  setInterval(purgeInactiveAccounts, HOUR_MS)
  setInterval(purgeOldInvites, HOUR_MS)
  setInterval(purgeOldReports, HOUR_MS)
  setInterval(cleanupMessagesAndGroups, HOUR_MS)
  setInterval(checkDiskSpace, 6 * HOUR_MS)
}

module.exports = { startJobs }
