import { Capacitor, registerPlugin } from '@capacitor/core'
import { KeychainAccess, SecureStorage } from '@aparajita/capacitor-secure-storage'

const NativeVaultGuard = registerPlugin('NativeVaultGuard')
const VAULT_KEY = 'private-notes-vault-v1'
const LEGACY_VAULT_KEY = 'encrypted-notes-vault'
const PBKDF2_ITERATIONS = 600000
const MIN_PASSWORD_LENGTH = 12
const MAX_PASSWORD_LENGTH = 1024
const MAX_FAILED_ATTEMPTS = 100
const SAVE_DELAY_MS = 300
const IDLE_LOCK_MS = 60 * 1000
const NATIVE_ATTEMPT_KEY = 'failed-attempt-state'
const NATIVE_DATA_KEY_PREFIX = 'vault-data-key.'
const NATIVE_STORAGE_PREFIX = 'private-notes-vault.'
const PASSWORD_VERIFIER = 'Private Notes native vault verifier v1'

const state = {
  unlocked: false,
  key: null,
  notes: [],
  activeId: null,
  search: '',
  status: '',
  saveQueue: Promise.resolve(),
  saveTimer: null,
  sessionGeneration: 0,
  authenticating: false,
  idleTimer: null,
  lockPromise: null,
  native: Capacitor.isNativePlatform(),
  android: Capacitor.getPlatform() === 'android',
  nativeReady: false,
  nativeError: '',
  orphanedAttemptState: null,
}

function escapeHtml(value = '') {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

function getRawVault() {
  return localStorage.getItem(VAULT_KEY) || localStorage.getItem(LEGACY_VAULT_KEY)
}

async function initializeNativeStorage() {
  if (!state.native) {
    state.nativeReady = true
    return
  }

  await SecureStorage.setKeyPrefix(NATIVE_STORAGE_PREFIX)
  await SecureStorage.setSynchronize(false)
  await SecureStorage.setDefaultKeychainAccess(KeychainAccess.whenPasscodeSetThisDeviceOnly)
  let nativeAttemptState = await readNativeAttemptState()
  if (state.android && !nativeAttemptState) {
    const legacyAttemptState = await SecureStorage.getItem(NATIVE_ATTEMPT_KEY)
    if (legacyAttemptState) {
      await storeAttemptState(JSON.parse(legacyAttemptState))
      await SecureStorage.removeItem(NATIVE_ATTEMPT_KEY)
      nativeAttemptState = legacyAttemptState
    }
  }
  if (nativeAttemptState && !getRawVault()) {
    const attempts = JSON.parse(nativeAttemptState)
    if (
      !attempts ||
      !Number.isInteger(attempts.count) ||
      !Number.isInteger(attempts.maximum) ||
      attempts.count < 0 ||
      attempts.maximum < 1 ||
      attempts.maximum > MAX_FAILED_ATTEMPTS
    ) {
      throw new Error('The secure failed-attempt record is invalid.')
    }
    if (attempts.count >= attempts.maximum) {
      state.nativeError = 'The failed-attempt limit was reached. This device is locked from creating another vault.'
    } else {
      await SecureStorage.removeItem(`${NATIVE_DATA_KEY_PREFIX}${attempts.vaultId}`)
      state.orphanedAttemptState = attempts
    }
  } else if (nativeAttemptState) {
    const attempts = JSON.parse(nativeAttemptState)
    if (
      !attempts ||
      !Number.isInteger(attempts.count) ||
      !Number.isInteger(attempts.maximum) ||
      attempts.count < 0 ||
      attempts.maximum < 1 ||
      attempts.maximum > MAX_FAILED_ATTEMPTS
    ) {
      throw new Error('The secure failed-attempt record is invalid.')
    }
    if (attempts.count >= attempts.maximum) {
      await eraseVault('The failed-attempt limit was reached. The local vault has been deleted.')
    }
  }
  state.nativeReady = true
}

async function getAttemptState(vault) {
  if (!state.native) {
    return vault.attempts || { count: 0, maximum: 5 }
  }

  const serialized = await readNativeAttemptState()
  if (!serialized) {
    throw new Error('Secure attempt data is missing. The vault is locked to prevent a reset.')
  }

  let attemptState
  try {
    attemptState = JSON.parse(serialized)
  } catch {
    throw new Error('Secure attempt data is damaged. The vault is locked.')
  }

  if (
    !attemptState ||
    attemptState.vaultId !== vault.vaultId ||
    !Number.isInteger(attemptState.count) ||
    !Number.isInteger(attemptState.maximum) ||
    attemptState.count < 0 ||
    attemptState.maximum < 1 ||
    attemptState.maximum > MAX_FAILED_ATTEMPTS
  ) {
    throw new Error('Secure attempt data does not match this vault. The vault is locked.')
  }

  return attemptState
}

async function readNativeAttemptState() {
  if (!state.native) return null
  if (state.android) {
    const result = await NativeVaultGuard.getAttemptState()
    return result.data || null
  }
  return SecureStorage.getItem(NATIVE_ATTEMPT_KEY)
}

async function storeAttemptState(attemptState) {
  if (!state.native) return
  if (state.android) {
    await NativeVaultGuard.setAttemptState({ data: JSON.stringify(attemptState) })
    return
  }
  await SecureStorage.setItem(NATIVE_ATTEMPT_KEY, JSON.stringify(attemptState))
}

async function removeNativeAttemptState() {
  if (state.android) {
    await NativeVaultGuard.removeAttemptState()
    return
  }
  await SecureStorage.removeItem(NATIVE_ATTEMPT_KEY)
}

function createNoteId() {
  if (typeof window.crypto.randomUUID === 'function') return window.crypto.randomUUID()
  return bytesToBase64(window.crypto.getRandomValues(new Uint8Array(16)))
}

function readVault() {
  const raw = getRawVault()
  if (!raw) return null

  let vault
  try {
    vault = JSON.parse(raw)
  } catch {
    throw new Error('The saved vault is damaged and cannot be read.')
  }

  if (!vault || typeof vault.salt !== 'string' || typeof vault.ciphertext !== 'string') {
    throw new Error('The saved vault is damaged and cannot be read.')
  }
  const hasValidSalt = base64ToBytes(vault.salt).length === 16
  const hasValidCiphertext = base64ToBytes(vault.ciphertext).length >= 16
  const validLegacyVault =
    (vault.version === 1 || vault.version === undefined) &&
    typeof vault.iv === 'string' &&
    base64ToBytes(vault.iv).length === 12
  const validNativeVault =
    (vault.version === 2 || vault.version === 3) &&
    typeof vault.vaultId === 'string' &&
    typeof vault.verifierIv === 'string' &&
    base64ToBytes(vault.verifierIv).length === 12 &&
    typeof vault.dataIv === 'string' &&
    base64ToBytes(vault.dataIv).length === 12 &&
    typeof vault.verifierCiphertext === 'string' &&
    base64ToBytes(vault.verifierCiphertext).length >= 16
  const validWrappedDataKey =
    vault.version === 3 &&
    typeof vault.wrappedDataKeyIv === 'string' &&
    base64ToBytes(vault.wrappedDataKeyIv).length === 12 &&
    typeof vault.wrappedDataKey === 'string' &&
    base64ToBytes(vault.wrappedDataKey).length === 48
  if (
    !hasValidSalt ||
    !hasValidCiphertext ||
    (!validLegacyVault && !validNativeVault) ||
    (vault.version === 3 && !validWrappedDataKey)
  ) {
    throw new Error('The saved vault is damaged and cannot be read.')
  }

  if (!vault.attempts && vault.version !== 2 && vault.version !== 3) {
    vault.attempts = { count: 0, maximum: 5 }
  }

  if (vault.attempts && (
    !Number.isInteger(vault.attempts.count) ||
    !Number.isInteger(vault.attempts.maximum) ||
    vault.attempts.count < 0 ||
    vault.attempts.maximum < 1 ||
    vault.attempts.maximum > MAX_FAILED_ATTEMPTS
  )) {
    throw new Error('The saved vault has invalid security settings.')
  }

  return vault
}

function bytesToBase64(bytes) {
  let binary = ''
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte)
  })
  return btoa(binary)
}

function base64ToBytes(value) {
  const binary = atob(value)
  const bytes = new Uint8Array(binary.length)
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index)
  }
  return bytes
}

async function deriveKey(password, salt, iterations = PBKDF2_ITERATIONS) {
  const passwordMaterial = await window.crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    'PBKDF2',
    false,
    ['deriveKey'],
  )

  return window.crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations,
      hash: 'SHA-256',
    },
    passwordMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  )
}

async function encryptNotes(notes, key, salt) {
  const iv = window.crypto.getRandomValues(new Uint8Array(12))
  const encrypted = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    new TextEncoder().encode(JSON.stringify(notes)),
  )

  return {
    version: 1,
    salt: bytesToBase64(salt),
    iv: bytesToBase64(iv),
    ciphertext: bytesToBase64(new Uint8Array(encrypted)),
  }
}

async function encryptNativeNotes(notes, key) {
  const dataIv = window.crypto.getRandomValues(new Uint8Array(12))
  const ciphertext = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: dataIv },
    key,
    new TextEncoder().encode(JSON.stringify(notes)),
  )
  return {
    dataIv: bytesToBase64(dataIv),
    ciphertext: bytesToBase64(new Uint8Array(ciphertext)),
  }
}

async function decryptNotes(vault, key) {
  const plaintext = await window.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: base64ToBytes(vault.iv) },
    key,
    base64ToBytes(vault.ciphertext),
  )
  const notes = JSON.parse(new TextDecoder().decode(plaintext))
  if (!Array.isArray(notes)) {
    throw new Error('The saved vault contains invalid note data.')
  }
  return notes
}

async function decryptNativeNotes(vault, key) {
  const plaintext = await window.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: base64ToBytes(vault.dataIv) },
    key,
    base64ToBytes(vault.ciphertext),
  )
  const notes = JSON.parse(new TextDecoder().decode(plaintext))
  if (!Array.isArray(notes)) {
    throw new Error('The saved vault contains invalid note data.')
  }
  return notes
}

async function createPasswordVerifier(verificationKey) {
  const verifierIv = window.crypto.getRandomValues(new Uint8Array(12))
  const verifierCiphertext = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: verifierIv },
    verificationKey,
    new TextEncoder().encode(PASSWORD_VERIFIER),
  )
  return {
    verifierIv: bytesToBase64(verifierIv),
    verifierCiphertext: bytesToBase64(new Uint8Array(verifierCiphertext)),
  }
}

async function verifyNativePassword(vault, verificationKey) {
  const verifier = await window.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: base64ToBytes(vault.verifierIv) },
    verificationKey,
    base64ToBytes(vault.verifierCiphertext),
  )
  if (new TextDecoder().decode(verifier) !== PASSWORD_VERIFIER) {
    throw new Error('The vault password verifier is invalid.')
  }
}

async function createNativeDataKey(passwordKey) {
  const rawKey = window.crypto.getRandomValues(new Uint8Array(32))
  try {
    const key = await window.crypto.subtle.importKey(
      'raw',
      rawKey,
      { name: 'AES-GCM' },
      false,
      ['encrypt', 'decrypt'],
    )
    return {
      key,
      ...(await wrapNativeDataKey(rawKey, passwordKey)),
    }
  } finally {
    rawKey.fill(0)
  }
}

async function loadLegacyNativeDataKey(vaultId) {
  const serializedKey = await SecureStorage.getItem(`${NATIVE_DATA_KEY_PREFIX}${vaultId}`)
  if (!serializedKey) {
    throw new Error('The device-bound encryption key is missing. The vault cannot be opened.')
  }
  const rawKey = base64ToBytes(serializedKey)
  if (rawKey.length !== 32) {
    rawKey.fill(0)
    throw new Error('The device-bound encryption key is damaged.')
  }
  return rawKey
}

async function wrapNativeDataKey(rawKey, passwordKey) {
  const wrappedDataKeyIv = window.crypto.getRandomValues(new Uint8Array(12))
  const wrappedDataKey = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: wrappedDataKeyIv },
    passwordKey,
    rawKey,
  )
  return {
    wrappedDataKeyIv: bytesToBase64(wrappedDataKeyIv),
    wrappedDataKey: bytesToBase64(new Uint8Array(wrappedDataKey)),
  }
}

async function unwrapNativeDataKey(vault, passwordKey) {
  const rawKey = new Uint8Array(await window.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: base64ToBytes(vault.wrappedDataKeyIv) },
    passwordKey,
    base64ToBytes(vault.wrappedDataKey),
  ))
  if (rawKey.length !== 32) {
    rawKey.fill(0)
    throw new Error('The wrapped device encryption key is damaged.')
  }
  try {
    return await window.crypto.subtle.importKey(
      'raw',
      rawKey,
      { name: 'AES-GCM' },
      false,
      ['encrypt', 'decrypt'],
    )
  } finally {
    rawKey.fill(0)
  }
}

function getActiveNote() {
  if (!state.activeId) return state.notes[0] || null
  return state.notes.find((note) => note.id === state.activeId) || state.notes[0] || null
}

function showStatus(message, isError = true) {
  state.status = message
  const status = document.getElementById('status-message') || document.getElementById('operation-message')
  if (status) {
    status.textContent = message
    status.classList.toggle('error', isError)
    status.classList.toggle('success', !isError)
  }
}

function clearSession() {
  window.clearTimeout(state.saveTimer)
  window.clearTimeout(state.idleTimer)
  state.sessionGeneration += 1
  state.unlocked = false
  state.key = null
  state.notes = []
  state.activeId = null
  state.search = ''
  state.saveQueue = Promise.resolve()
}

function scheduleIdleLock() {
  window.clearTimeout(state.idleTimer)
  if (!state.unlocked) return
  state.idleTimer = window.setTimeout(() => {
    void lockVault('Vault locked after 1 minute of inactivity.', true)
  }, IDLE_LOCK_MS)
}

function renderAuthScreen() {
  let hasVault = false
  let vaultError = ''
  try {
    hasVault = Boolean(readVault())
  } catch (error) {
    hasVault = true
    vaultError = error.message
  }

  const info = `
    <details class="security-info">
      <summary>How your privacy works</summary>
      <div class="info-content">
        <p>Your notes are encrypted on this device with AES-256-GCM. ${state.native
          ? 'A random data key is encrypted with a key derived from your password using PBKDF2-SHA-256 (600,000 iterations). Only the encrypted key and encrypted vault are stored on this device.'
          : 'The key is derived from your password using PBKDF2-SHA-256.'} Only the encrypted vault is saved in ${state.native ? 'this app’s local storage' : 'this browser’s local storage'}; there is no account server, database, analytics, or cloud sync.</p>
        <p>The app locks after one minute without activity and when it leaves the foreground. ${state.native
          ? `${state.android ? 'Android failed-attempt state is encrypted with an Android Keystore key and synchronously committed before a failed login is reported.' : 'iOS failed-attempt state is stored in a device-only Keychain item.'} A reached limit leaves a secure lockout marker and disables creating a replacement vault. Rooted/jailbroken devices and instrumented app code remain outside this protection.`
          : 'The website version stores failed-attempt state in browser data which can be changed by someone controlling the browser. Use the native Android/iOS app for platform secure storage of this state.'} Choose a long, unique password.</p>
        <p>This is client-side software, so its published source can be inspected and reverse-engineered. Someone with a copy of the encrypted vault can guess passwords offline; the failed-attempt limit cannot stop that. A compromised phone or altered app can expose notes. No app can guarantee protection from coercion, keyloggers, or every storage copy. Do not rely on this app as the only protection for information whose exposure could put you in danger.</p>
        <p>${state.native         ? 'Keep your device updated and use its screen lock. iOS requires a device passcode for this vault key. Native vault data is local to this app and does not synchronize.' : 'Use HTTPS and keep your device and browser trusted and up to date. The vault is stored only in this browser profile and is not synchronized between devices.'}</p>
      </div>
    </details>
  `

  document.querySelector('#app').innerHTML = `
    <main class="auth-shell">
      <section class="auth-panel">
        <div class="brand-mark" aria-hidden="true">e<span class="brand-initial">n</span></div>
        <p class="eyebrow">ENCRONOTE</p>
        <h1>${hasVault ? 'Unlock your vault' : 'A quiet place for your thoughts'}</h1>
        <p class="subtitle">
          ${hasVault
            ? 'Your encrypted notes stay on this device.'
            : 'Create a local vault. Your password never leaves this device.'}
        </p>

        ${vaultError ? '<p class="form-message error" role="alert">The saved vault could not be read. Do not clear browser storage if you need to recover it.</p>' : ''}
        <form id="auth-form" class="auth-form">
          <label for="password">Master password</label>
          <input
            id="password"
            name="password"
            type="password"
            minlength="${MIN_PASSWORD_LENGTH}"
            maxlength="${MAX_PASSWORD_LENGTH}"
            placeholder="At least ${MIN_PASSWORD_LENGTH} characters"
            autocomplete="${hasVault ? 'current-password' : 'new-password'}"
            required
          />
          ${hasVault ? '' : `
            <label for="confirm-password">Confirm password</label>
            <input
              id="confirm-password"
              name="confirm"
              type="password"
              minlength="${MIN_PASSWORD_LENGTH}"
              maxlength="${MAX_PASSWORD_LENGTH}"
              placeholder="Enter it again"
              autocomplete="new-password"
              required
            />
            ${state.orphanedAttemptState
              ? `<p class="field-hint">This device keeps the previous secure attempt limit. Your new vault inherits ${state.orphanedAttemptState.maximum - state.orphanedAttemptState.count} remaining attempt(s); the limit cannot be increased.</p>`
              : `
                <label for="attempt-limit">Erase vault after this many failed attempts</label>
                <input
                  id="attempt-limit"
                  name="attemptLimit"
                  type="number"
                  min="1"
                  max="${MAX_FAILED_ATTEMPTS}"
                  value="5"
                  required
                />
                <p class="field-hint">Choose between 1 and ${MAX_FAILED_ATTEMPTS} attempts.</p>
              `}
          `}
          <button class="primary-button submit-button" type="submit">
            ${hasVault ? 'Unlock vault' : 'Create vault'}
          </button>
        </form>
        <p id="status-message" class="form-message ${state.status ? 'error' : ''}" role="status">${escapeHtml(state.status)}</p>
        ${info}
        ${state.native ? '' : '<a class="android-download-link" href="/download">Get the Android app</a>'}
      </section>
    </main>
  `

  document.getElementById('auth-form')?.addEventListener('submit', handleAuthSubmit)
}

async function handleAuthSubmit(event) {
  event.preventDefault()
  if (state.authenticating) return
  state.authenticating = true
  const submitButton = event.currentTarget.querySelector('button[type="submit"]')
  if (submitButton) submitButton.disabled = true
  try {
    await processAuthSubmit(event)
  } catch (error) {
    showStatus(`Could not complete that action: ${error.message}`)
  } finally {
    state.authenticating = false
    const passwordInput = document.getElementById('password')
    const confirmationInput = document.getElementById('confirm-password')
    if (passwordInput) passwordInput.value = ''
    if (confirmationInput) confirmationInput.value = ''
    const currentButton = document.querySelector('#auth-form button[type="submit"]')
    if (currentButton) currentButton.disabled = false
  }
}

async function processAuthSubmit(event) {
  const form = event.currentTarget
  const data = new FormData(form)
  const password = String(data.get('password') || '')
  const confirmation = String(data.get('confirm') || '')
  const passwordInput = document.getElementById('password')
  const confirmationInput = document.getElementById('confirm-password')
  if (passwordInput) passwordInput.value = ''
  if (confirmationInput) confirmationInput.value = ''
  const hasVault = Boolean(getRawVault())

  if (password.length < MIN_PASSWORD_LENGTH) {
    showStatus(`Use a password with at least ${MIN_PASSWORD_LENGTH} characters.`)
    return
  }
  if (password.length > MAX_PASSWORD_LENGTH) {
    showStatus(`Use a password with no more than ${MAX_PASSWORD_LENGTH} characters.`)
    return
  }

  if (!hasVault) {
    const maximum = state.orphanedAttemptState
      ? state.orphanedAttemptState.maximum
      : Number(data.get('attemptLimit'))
    if (password !== confirmation) {
      showStatus('The passwords do not match.')
      return
    }
    if (!Number.isInteger(maximum) || maximum < 1 || maximum > MAX_FAILED_ATTEMPTS) {
      showStatus(`Choose a failed-attempt limit between 1 and ${MAX_FAILED_ATTEMPTS}.`)
      return
    }

    let vaultId
    let vaultStored = false
    try {
      const salt = window.crypto.getRandomValues(new Uint8Array(16))
      vaultId = createNoteId()
      const attemptState = state.orphanedAttemptState
        ? { ...state.orphanedAttemptState, vaultId }
        : { vaultId, count: 0, maximum }
      let key
      let vault
      if (state.native) {
        const passwordKey = await deriveKey(password, salt)
        const verifier = await createPasswordVerifier(passwordKey)
        const dataKey = await createNativeDataKey(passwordKey)
        key = dataKey.key
        const encrypted = await encryptNativeNotes([], key)
        vault = {
          version: 3,
          vaultId,
          salt: bytesToBase64(salt),
          ...verifier,
          wrappedDataKeyIv: dataKey.wrappedDataKeyIv,
          wrappedDataKey: dataKey.wrappedDataKey,
          ...encrypted,
        }
        await storeAttemptState(attemptState)
      } else {
        key = await deriveKey(password, salt)
        vault = {
          ...(await encryptNotes([], key, salt)),
          vaultId,
          attempts: attemptState,
        }
      }
      try {
        localStorage.setItem(VAULT_KEY, JSON.stringify(vault))
        vaultStored = true
      } catch (storageError) {
        throw storageError
      }
      localStorage.removeItem(LEGACY_VAULT_KEY)
      state.orphanedAttemptState = null
      state.key = key
      state.notes = []
      state.unlocked = true
      state.status = ''
      render()
    } catch (error) {
      if (state.native && !vaultStored && vaultId) {
        try {
          await SecureStorage.removeItem(`${NATIVE_DATA_KEY_PREFIX}${vaultId}`)
          if (state.orphanedAttemptState) {
            await storeAttemptState(state.orphanedAttemptState)
          } else {
            await removeNativeAttemptState()
          }
        } catch (cleanupError) {
          state.nativeError = `Could not safely roll back secure vault setup: ${cleanupError.message}`
          render()
          return
        }
      }
      if (state.native && vaultStored) {
        state.nativeError = `The vault was saved but setup could not finish: ${error.message}`
        render()
        return
      }
      showStatus(`Could not create the local vault: ${error.message}`)
    }
    return
  }

  let vault
  try {
    vault = readVault()
  } catch (error) {
    if (state.native) {
      state.nativeError = `The local vault could not be verified: ${error.message}`
      render()
      return
    }
    showStatus(error.message)
    return
  }

  let attempts
  try {
    attempts = await getAttemptState(vault)
  } catch (error) {
    if (state.native) {
      state.nativeError = error.message
      render()
      return
    }
    showStatus(error.message)
    return
  }

  if (attempts.count >= attempts.maximum) {
    await eraseVault('The failed-attempt limit was already reached. The local vault has been deleted.')
    return
  }

  try {
    let activeKey
    let notes
    let updatedVault
    let legacyDataKeyId = null
    if (state.native && vault.version === 3) {
      const passwordKey = await deriveKey(password, base64ToBytes(vault.salt))
      await verifyNativePassword(vault, passwordKey)
      activeKey = await unwrapNativeDataKey(vault, passwordKey)
      notes = await decryptNativeNotes(vault, activeKey)
      updatedVault = vault
    } else if (state.native && vault.version === 2) {
      const passwordKey = await deriveKey(password, base64ToBytes(vault.salt))
      await verifyNativePassword(vault, passwordKey)
      const rawDataKey = await loadLegacyNativeDataKey(vault.vaultId)
      try {
        activeKey = await window.crypto.subtle.importKey(
          'raw',
          rawDataKey,
          { name: 'AES-GCM' },
          false,
          ['encrypt', 'decrypt'],
        )
        notes = await decryptNativeNotes(vault, activeKey)
        updatedVault = {
          ...vault,
          version: 3,
          ...(await wrapNativeDataKey(rawDataKey, passwordKey)),
        }
        legacyDataKeyId = vault.vaultId
      } finally {
        rawDataKey.fill(0)
      }
    } else if (state.native) {
      const oldKey = await deriveKey(
        password,
        base64ToBytes(vault.salt),
        vault.version === undefined ? 250000 : PBKDF2_ITERATIONS,
      )
      notes = await decryptNotes(vault, oldKey)
      const salt = window.crypto.getRandomValues(new Uint8Array(16))
      const vaultId = vault.vaultId || attempts.vaultId || createNoteId()
      const passwordKey = await deriveKey(password, salt)
      const verifier = await createPasswordVerifier(passwordKey)
      const dataKey = await createNativeDataKey(passwordKey)
      activeKey = dataKey.key
      updatedVault = {
        version: 3,
        vaultId,
        salt: bytesToBase64(salt),
        ...verifier,
        wrappedDataKeyIv: dataKey.wrappedDataKeyIv,
        wrappedDataKey: dataKey.wrappedDataKey,
        ...(await encryptNativeNotes(notes, activeKey)),
      }
      legacyDataKeyId = vault.vaultId || null
    } else {
      const key = await deriveKey(
        password,
        base64ToBytes(vault.salt),
        vault.version === undefined ? 250000 : PBKDF2_ITERATIONS,
      )
      notes = await decryptNotes(vault, key)
      activeKey = key
      if (vault.version === undefined) {
        const salt = window.crypto.getRandomValues(new Uint8Array(16))
        activeKey = await deriveKey(password, salt)
        updatedVault = {
          ...(await encryptNotes(notes, activeKey, salt)),
          vaultId: createNoteId(),
          attempts: { count: 0, maximum: vault.attempts.maximum },
        }
      } else {
        vault.attempts.count = 0
        updatedVault = vault
      }
    }

    if (state.native) {
      await storeAttemptState({ ...attempts, count: 0, vaultId: updatedVault.vaultId })
    } else {
      if (updatedVault.attempts) {
        updatedVault.attempts.count = 0
      }
    }
    localStorage.setItem(VAULT_KEY, JSON.stringify(updatedVault))
    if (state.native && legacyDataKeyId) {
      await SecureStorage.removeItem(`${NATIVE_DATA_KEY_PREFIX}${legacyDataKeyId}`)
    }
    if (getRawVault() && localStorage.getItem(LEGACY_VAULT_KEY)) {
      localStorage.removeItem(LEGACY_VAULT_KEY)
    }
    state.key = activeKey
    state.notes = notes
    state.unlocked = true
    state.activeId = notes[0]?.id || null
    state.status = ''
    render()
  } catch (error) {
    if (error.name !== 'OperationError') {
      if (state.native) {
        state.nativeError = `The vault or secure storage could not be verified: ${error.message}`
        render()
        return
      }
      showStatus(`Could not unlock the vault: ${error.message}`)
      return
    }

    attempts.count += 1
    if (attempts.count >= attempts.maximum) {
      await eraseVault('Too many failed attempts. The local vault has been deleted.')
      return
    }

    try {
      if (state.native) {
        await storeAttemptState(attempts)
      } else {
        vault.attempts = attempts
        localStorage.setItem(VAULT_KEY, JSON.stringify(vault))
      }
      localStorage.removeItem(LEGACY_VAULT_KEY)
    } catch (storageError) {
      if (state.native) {
        state.nativeError = `Secure attempt storage failed: ${storageError.message}`
        render()
        return
      }
      showStatus(`Could not securely save the failed-attempt counter: ${storageError.message}. The vault remains locked.`)
      return
    }

    state.status = `Incorrect password. ${attempts.maximum - attempts.count} attempt(s) remaining.`
    renderAuthScreen()
  }
}

async function eraseVault(message) {
  try {
    if (state.native) {
      const tombstone = await readNativeAttemptState()
      if (!tombstone) throw new Error('The secure lockout record is missing.')
      const attemptState = JSON.parse(tombstone)
      if (!Number.isInteger(attemptState.maximum) || !attemptState.vaultId) {
        throw new Error('The secure lockout record is invalid.')
      }
      attemptState.count = attemptState.maximum
      await storeAttemptState(attemptState)
      await SecureStorage.removeItem(`${NATIVE_DATA_KEY_PREFIX}${attemptState.vaultId}`)
      state.nativeError = 'The failed-attempt limit was reached. This device is locked from creating another vault.'
    } else {
      const vault = readVault()
      if (vault) {
        vault.attempts = {
          ...(vault.attempts || {}),
          count: vault.attempts?.maximum || 5,
          maximum: vault.attempts?.maximum || 5,
        }
        localStorage.setItem(VAULT_KEY, JSON.stringify(vault))
      }
    }
    clearSession()
    localStorage.removeItem(VAULT_KEY)
    localStorage.removeItem(LEGACY_VAULT_KEY)
    state.status = message
  } catch (error) {
    clearSession()
    state.status = `Could not delete the local vault: ${error.message}`
    if (state.native) {
      state.nativeError = `Secure lockout could not be confirmed: ${error.message}`
    }
  }
  render()
}

async function saveVault() {
  if (!state.key) throw new Error('The vault is locked.')
  const snapshot = JSON.stringify(state.notes)
  const key = state.key
  const generation = state.sessionGeneration
  const previousSave = state.saveQueue
  const nextSave = previousSave.then(async () => {
    const currentVault = readVault()
    let savedVault
    if (state.native) {
      if (currentVault.version !== 3) {
        throw new Error('The device vault must be upgraded before saving.')
      }
      savedVault = {
        ...currentVault,
        ...(await encryptNativeNotes(JSON.parse(snapshot), key)),
      }
    } else {
      savedVault = {
        ...(await encryptNotes(JSON.parse(snapshot), key, base64ToBytes(currentVault.salt))),
        vaultId: currentVault.vaultId,
        ...(currentVault.attempts ? { attempts: currentVault.attempts } : {}),
      }
    }
    if (!state.unlocked || state.sessionGeneration !== generation) return
    localStorage.setItem(VAULT_KEY, JSON.stringify(savedVault))
    localStorage.removeItem(LEGACY_VAULT_KEY)
  })
  state.saveQueue = nextSave.catch(() => {})
  return nextSave
}

function getNotePreview(note) {
  const text = note.content.replace(/\s+/g, ' ').trim()
  return text || 'No additional text'
}

function formatDate(value) {
  if (!value) return ''
  return new Date(value).toLocaleDateString('en', { month: 'short', day: 'numeric' })
}

function renderApp() {
  scheduleIdleLock()
  const active = getActiveNote()
  const filteredNotes = [...state.notes]
    .sort((left, right) => new Date(right.updatedAt) - new Date(left.updatedAt))
    .filter((note) => `${note.title} ${note.content}`.toLowerCase().includes(state.search.toLowerCase()))

  document.querySelector('#app').innerHTML = `
    <main class="app-shell">
      <aside class="sidebar">
        <header class="sidebar-header">
          <a class="wordmark" href="#" aria-label="EncroNote home"><span class="brand-mark small">e<span class="brand-initial">n</span></span> encronote</a>
          <button class="icon-button" id="new-note" type="button" aria-label="Create note" title="New note">+</button>
        </header>
        <label class="search-box">
          <span aria-hidden="true">⌕</span>
          <input id="search-input" type="search" value="${escapeHtml(state.search)}" placeholder="Search" aria-label="Search notes" autocomplete="off" autocorrect="off" spellcheck="false" />
        </label>
        <p class="section-label">YOUR NOTES <span>${state.notes.length}</span></p>
        <nav class="note-list" aria-label="Your notes">
          ${filteredNotes.length
            ? filteredNotes.map((note) => `
              <button type="button" class="note-item ${note.id === active?.id ? 'selected' : ''}" data-id="${escapeHtml(note.id)}">
                <span class="note-item-top"><span class="note-title">${escapeHtml(note.title || 'Untitled')}</span><span class="note-date">${formatDate(note.updatedAt)}</span></span>
                <span class="note-preview">${escapeHtml(getNotePreview(note))}</span>
              </button>
            `).join('')
            : `<p class="empty-state">${state.search ? 'No notes found.' : 'Your notes will appear here.'}</p>`}
        </nav>
        <footer class="sidebar-footer">
          <span class="local-indicator"><span></span> Stored on this device</span>
          <button class="text-button" id="lock-vault" type="button">Lock vault</button>
        </footer>
      </aside>
      <section class="editor">
        ${active ? `
          <header class="editor-header">
            <span id="save-status" class="save-status">Saved locally</span>
            <button class="text-button delete-button" id="delete-note" type="button">Delete note</button>
          </header>
          <input id="note-title" class="note-heading" type="text" value="${escapeHtml(active.title || '')}" placeholder="Untitled" aria-label="Note title" autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false" />
          <textarea id="note-content" placeholder="Start writing..." aria-label="Note content" autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false">${escapeHtml(active.content || '')}</textarea>
        ` : `
          <div class="welcome">
            <span class="welcome-mark">e<span class="brand-initial">n</span></span>
            <p>${state.search ? 'No matching notes' : 'Nothing here yet'}</p>
            <button type="button" class="text-button" id="empty-new-note">Create a note</button>
          </div>
        `}
      </section>
      <p id="operation-message" class="operation-message" role="status">${escapeHtml(state.status)}</p>
      <details class="app-info">
        <summary>Privacy & security</summary>
        <div class="info-content">
          <p>Notes are encrypted using AES-256-GCM. ${state.native
            ? 'The random data key is wrapped by a key derived from your master password using PBKDF2-SHA-256 (600,000 iterations). Only its encrypted form is stored with the vault.'
            : 'The key is derived from your master password with PBKDF2-SHA-256 (600,000 iterations).'} Titles and note content are stored only as ciphertext; search runs in memory after unlock and is not saved.</p>
          <p>No server, database, analytics, or cloud sync is used. ${state.native
            ? `${state.android ? 'The vault belongs to this app installation; Android saves the encrypted failed-attempt counter synchronously using an Android Keystore key.' : 'The vault belongs to this app installation; failed-attempt state is stored in the device-only Keychain.'} It does not sync.`
            : 'The website vault belongs to this browser profile; its attempt counter is editable browser data and does not provide a tamper-proof lockout.'} The app locks after one minute of inactivity and when it leaves the foreground.</p>
          <p>Because this is client-side software, its source can be inspected and reverse-engineered. A copied vault can be attacked offline, and the website's publisher or a compromised device can replace or inspect app code. The attempt limit cannot stop offline guesses. This app cannot protect against coercion, keyloggers, or a compromised phone; do not rely on it as the only safeguard for information whose exposure could put you in danger.</p>
          <p>${state.native
            ? 'This is the native mobile build using platform secure storage. Keep the app installed from a trusted, signed source and update it only through the official download page.'
            : 'To install the website version, use your browser’s “Add to Home Screen” option. It does not include native secure storage and is not an App Store or Google Play listing.'}</p>
        </div>
      </details>
    </main>
  `

  document.getElementById('new-note')?.addEventListener('click', createNote)
  document.getElementById('empty-new-note')?.addEventListener('click', createNote)
  document.getElementById('lock-vault')?.addEventListener('click', () => lockVault())
  document.getElementById('delete-note')?.addEventListener('click', deleteCurrentNote)

  document.querySelectorAll('.note-item').forEach((button) => {
    button.addEventListener('click', () => {
      state.activeId = button.dataset.id
      render()
    })
  })

  document.getElementById('search-input')?.addEventListener('input', (event) => {
    state.search = event.currentTarget.value
    const cursor = event.currentTarget.selectionStart
    render()
    const search = document.getElementById('search-input')
    search.focus()
    search.setSelectionRange(cursor, cursor)
  })

  const updateNote = () => {
    const note = getActiveNote()
    if (!note) return
    note.title = document.getElementById('note-title').value
    note.content = document.getElementById('note-content').value
    note.updatedAt = new Date().toISOString()
    const noteItem = [...document.querySelectorAll('.note-item')]
      .find((item) => item.dataset.id === note.id)
    if (noteItem) {
      noteItem.querySelector('.note-title').textContent = note.title || 'Untitled'
      noteItem.querySelector('.note-preview').textContent = getNotePreview(note)
      noteItem.querySelector('.note-date').textContent = formatDate(note.updatedAt)
    }
    const saveStatus = document.getElementById('save-status')
    saveStatus.textContent = 'Saving…'
    window.clearTimeout(state.saveTimer)
    state.saveTimer = window.setTimeout(async () => {
      try {
        await saveVault()
        if (document.getElementById('save-status')) {
          document.getElementById('save-status').textContent = 'Saved locally'
        }
      } catch (error) {
        if (document.getElementById('save-status')) {
          document.getElementById('save-status').textContent = `Save failed: ${error.message}`
        }
      }
    }, SAVE_DELAY_MS)
  }

  document.getElementById('note-title')?.addEventListener('input', updateNote)
  document.getElementById('note-content')?.addEventListener('input', updateNote)
  const appShell = document.querySelector('.app-shell')
  for (const eventName of ['pointerdown', 'keydown', 'touchstart']) {
    appShell?.addEventListener(eventName, scheduleIdleLock, { passive: true })
  }
}

async function createNote() {
  const note = {
    id: createNoteId(),
    title: '',
    content: '',
    updatedAt: new Date().toISOString(),
  }
  state.notes.unshift(note)
  state.activeId = note.id
  renderApp()
  document.getElementById('note-title')?.focus()
  try {
    await saveVault()
  } catch (error) {
    showStatus(`Could not save note: ${error.message}`)
  }
}

async function lockVault(message = '', forceLock = false) {
  if (state.lockPromise) return state.lockPromise
  state.lockPromise = finishLockVault(message, forceLock)
  try {
    await state.lockPromise
  } finally {
    state.lockPromise = null
  }
}

async function finishLockVault(message = '', forceLock = false) {
  window.clearTimeout(state.saveTimer)
  window.clearTimeout(state.idleTimer)
  const app = document.querySelector('#app')
  if (app) {
    app.innerHTML = `
      <main class="auth-shell">
        <section class="auth-panel" role="status" aria-live="polite">
          <div class="brand-mark" aria-hidden="true">e<span class="brand-initial">n</span></div>
          <p class="eyebrow">ENCRONOTE</p>
          <h1>Locking your vault</h1>
          <p class="subtitle">Securing your notes on this device…</p>
        </section>
      </main>
    `
  }
  let saveError = null
  try {
    await saveVault()
  } catch (error) {
    saveError = error
    if (!forceLock) {
      showStatus(`Could not save before locking: ${error.message}`)
      scheduleIdleLock()
      return
    }
  }

  clearSession()
  state.status = saveError
    ? `Vault locked, but the latest changes could not be saved: ${saveError.message}`
    : message
  render()
}

async function deleteCurrentNote() {
  const active = getActiveNote()
  if (!active || !window.confirm('Delete this note permanently from this browser?')) return

  state.notes = state.notes.filter((note) => note.id !== active.id)
  state.activeId = state.notes[0]?.id || null
  renderApp()
  try {
    await saveVault()
  } catch (error) {
    showStatus(`Could not save changes: ${error.message}`)
  }
}

function render() {
  if (!window.crypto?.subtle) {
    document.querySelector('#app').innerHTML = `
      <main class="auth-shell">
        <section class="auth-panel">
          <h1>Secure browser required</h1>
          <p class="subtitle">This app needs the Web Crypto API. Open it in a modern browser over HTTPS or localhost.</p>
        </section>
      </main>
    `
    return
  }

  if (state.nativeError && !state.nativeReady) {
    document.querySelector('#app').innerHTML = `
      <main class="auth-shell">
        <section class="auth-panel">
          <h1>Secure storage unavailable</h1>
          <p class="subtitle">${escapeHtml(state.nativeError)}</p>
        </section>
      </main>
    `
    return
  }

  if (state.native && state.nativeError) {
    document.querySelector('#app').innerHTML = `
      <main class="auth-shell">
        <section class="auth-panel">
          <h1>Vault unavailable</h1>
          <p class="subtitle">${escapeHtml(state.nativeError)}</p>
          <p class="field-hint">${escapeHtml(state.nativeError.includes('failed-attempt limit') || state.nativeError.includes('lockout record') ? 'This lockout is intentional. The app will not reset secure attempt data to create another vault.' : 'The app is locked because secure storage could not be verified. Do not clear app data or restore a backup to bypass this check.')}</p>
        </section>
      </main>
    `
    return
  }

  if (state.unlocked) renderApp()
  else renderAuthScreen()
}

window.addEventListener('storage', (event) => {
  if (event.key === VAULT_KEY && event.newValue !== event.oldValue && state.unlocked) {
    clearSession()
    state.status = event.newValue === null
      ? 'The local vault was deleted in another tab.'
      : 'The local vault changed in another tab. Unlock again to continue.'
    render()
  }
})

document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'hidden' && state.unlocked) {
    void lockVault('Vault locked when the app left the foreground.', true)
  }
})

if (!state.native && 'serviceWorker' in navigator && window.isSecureContext) {
  navigator.serviceWorker.register('/sw.js').catch((error) => {
    console.error('Could not register the offline app shell:', error)
  })
}

void initializeNativeStorage()
  .then(render)
  .catch((error) => {
    state.nativeError = `Native secure storage could not be initialized: ${error.message}`
    state.nativeReady = false
    render()
  })
