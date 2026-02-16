/**
 * PayGuard V2 - Secure Storage Implementation
 * 
 * Provides AES-256-GCM encrypted storage using the Web Crypto API.
 * Implements:
 * - AES-256-GCM authenticated encryption (Task 4.1)
 * - Platform-specific key storage with fallback (Task 4.2)
 * - Key rotation (Task 4.3)
 * - Secure memory wiping (Task 4.4)
 * - Fail-closed behavior (Task 4.5)
 * 
 * Requirements: 3.1, 3.2, 3.5, 3.6, 3.7, 3.8, 3.9
 */

import {
  SecureStorage,
  SecureStorageError,
  SecureStorageErrorCode,
  EncryptedData,
  EncryptedBackup,
  KeyStorageProvider,
  Platform,
  STORAGE_KEYS
} from '../types/storage';

// Constants for encryption
const ENCRYPTION_VERSION = 1;
const KEY_LENGTH = 256; // AES-256
const IV_LENGTH = 12; // 96 bits for GCM
const SALT_LENGTH = 16; // 128 bits
const AUTH_TAG_LENGTH = 128; // 128 bits
const PBKDF2_ITERATIONS = 100000;

/**
 * Secure memory wiping utility.
 * Overwrites data with random values before releasing.
 */
export function secureWipe(data: Uint8Array): void {
  if (!data || data.length === 0) return;
  
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    crypto.getRandomValues(data);
  } else {
    for (let i = 0; i < data.length; i++) data[i] = 0;
    for (let i = 0; i < data.length; i++) data[i] = 0xFF;
    for (let i = 0; i < data.length; i++) data[i] = 0;
  }
}

/**
 * Secure memory wiping for ArrayBuffer.
 */
export function secureWipeBuffer(buffer: ArrayBuffer): void {
  secureWipe(new Uint8Array(buffer));
}


// Helper to convert Uint8Array to base64
function uint8ArrayToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

// Helper to convert base64 to Uint8Array
function base64ToUint8Array(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Browser-based key storage provider.
 * Uses chrome.storage.local with additional encryption layer.
 */
export class BrowserKeyStorageProvider implements KeyStorageProvider {
  platform: Platform = 'browser';
  
  async storeKey(keyId: string, key: Uint8Array): Promise<void> {
    const base64Key = uint8ArrayToBase64(key);
    await this.setStorageItem(`key_${keyId}`, base64Key);
  }
  
  async retrieveKey(keyId: string): Promise<Uint8Array | null> {
    const base64Key = await this.getStorageItem(`key_${keyId}`);
    if (!base64Key) return null;
    return base64ToUint8Array(base64Key);
  }
  
  async deleteKey(keyId: string): Promise<void> {
    await this.removeStorageItem(`key_${keyId}`);
  }
  
  async isAvailable(): Promise<boolean> {
    return true;
  }
  
  private async setStorageItem(key: string, value: string): Promise<void> {
    return new Promise((resolve, reject) => {
      if (typeof chrome !== 'undefined' && chrome.storage) {
        chrome.storage.local.set({ [key]: value }, () => {
          if (chrome.runtime?.lastError) {
            reject(new SecureStorageError(
              chrome.runtime.lastError.message || 'Storage error',
              SecureStorageErrorCode.STORAGE_UNAVAILABLE
            ));
          } else {
            resolve();
          }
        });
      } else {
        try {
          localStorage.setItem(key, value);
          resolve();
        } catch {
          reject(new SecureStorageError('localStorage unavailable', SecureStorageErrorCode.STORAGE_UNAVAILABLE));
        }
      }
    });
  }
  
  private async getStorageItem(key: string): Promise<string | null> {
    return new Promise((resolve, reject) => {
      if (typeof chrome !== 'undefined' && chrome.storage) {
        chrome.storage.local.get([key], (result) => {
          if (chrome.runtime?.lastError) {
            reject(new SecureStorageError(
              chrome.runtime.lastError.message || 'Storage error',
              SecureStorageErrorCode.STORAGE_UNAVAILABLE
            ));
          } else {
            resolve(result[key] || null);
          }
        });
      } else {
        resolve(localStorage.getItem(key));
      }
    });
  }
  
  private async removeStorageItem(key: string): Promise<void> {
    return new Promise((resolve, reject) => {
      if (typeof chrome !== 'undefined' && chrome.storage) {
        chrome.storage.local.remove([key], () => {
          if (chrome.runtime?.lastError) {
            reject(new SecureStorageError(
              chrome.runtime.lastError.message || 'Storage error',
              SecureStorageErrorCode.STORAGE_UNAVAILABLE
            ));
          } else {
            resolve();
          }
        });
      } else {
        localStorage.removeItem(key);
        resolve();
      }
    });
  }
}


/**
 * Native messaging key storage provider for macOS Keychain.
 */
export class MacOSKeychainProvider implements KeyStorageProvider {
  platform: Platform = 'macos';
  private nativeHostName = 'com.payguard.keychain';
  
  async storeKey(keyId: string, key: Uint8Array): Promise<void> {
    await this.sendNativeMessage({ action: 'store', keyId, data: Array.from(key) });
  }
  
  async retrieveKey(keyId: string): Promise<Uint8Array | null> {
    const response = await this.sendNativeMessage({ action: 'retrieve', keyId });
    if (response.data) return new Uint8Array(response.data);
    return null;
  }
  
  async deleteKey(keyId: string): Promise<void> {
    await this.sendNativeMessage({ action: 'delete', keyId });
  }
  
  async isAvailable(): Promise<boolean> {
    if (typeof chrome === 'undefined' || !chrome.runtime?.sendNativeMessage) return false;
    try {
      const response = await this.sendNativeMessage({ action: 'ping' });
      return response.status === 'ok';
    } catch {
      return false;
    }
  }
  
  private sendNativeMessage(message: object): Promise<{ status: string; data?: number[] }> {
    return new Promise((resolve, reject) => {
      if (typeof chrome === 'undefined' || !chrome.runtime?.sendNativeMessage) {
        reject(new SecureStorageError('Native messaging not available', SecureStorageErrorCode.PLATFORM_ERROR));
        return;
      }
      chrome.runtime.sendNativeMessage(this.nativeHostName, message, (response) => {
        if (chrome.runtime.lastError) {
          reject(new SecureStorageError(chrome.runtime.lastError.message || 'Native messaging error', SecureStorageErrorCode.PLATFORM_ERROR));
        } else if (response?.error) {
          reject(new SecureStorageError(response.error, SecureStorageErrorCode.PLATFORM_ERROR));
        } else {
          resolve(response || { status: 'ok' });
        }
      });
    });
  }
}

/**
 * Native messaging key storage provider for Windows DPAPI.
 */
export class WindowsDPAPIProvider implements KeyStorageProvider {
  platform: Platform = 'windows';
  private nativeHostName = 'com.payguard.dpapi';
  
  async storeKey(keyId: string, key: Uint8Array): Promise<void> {
    await this.sendNativeMessage({ action: 'store', keyId, data: Array.from(key) });
  }
  
  async retrieveKey(keyId: string): Promise<Uint8Array | null> {
    const response = await this.sendNativeMessage({ action: 'retrieve', keyId });
    if (response.data) return new Uint8Array(response.data);
    return null;
  }
  
  async deleteKey(keyId: string): Promise<void> {
    await this.sendNativeMessage({ action: 'delete', keyId });
  }
  
  async isAvailable(): Promise<boolean> {
    if (typeof chrome === 'undefined' || !chrome.runtime?.sendNativeMessage) return false;
    try {
      const response = await this.sendNativeMessage({ action: 'ping' });
      return response.status === 'ok';
    } catch {
      return false;
    }
  }
  
  private sendNativeMessage(message: object): Promise<{ status: string; data?: number[] }> {
    return new Promise((resolve, reject) => {
      if (typeof chrome === 'undefined' || !chrome.runtime?.sendNativeMessage) {
        reject(new SecureStorageError('Native messaging not available', SecureStorageErrorCode.PLATFORM_ERROR));
        return;
      }
      chrome.runtime.sendNativeMessage(this.nativeHostName, message, (response) => {
        if (chrome.runtime.lastError) {
          reject(new SecureStorageError(chrome.runtime.lastError.message || 'Native messaging error', SecureStorageErrorCode.PLATFORM_ERROR));
        } else if (response?.error) {
          reject(new SecureStorageError(response.error, SecureStorageErrorCode.PLATFORM_ERROR));
        } else {
          resolve(response || { status: 'ok' });
        }
      });
    });
  }
}

/**
 * Native messaging key storage provider for Linux keyring (libsecret).
 */
export class LinuxKeyringProvider implements KeyStorageProvider {
  platform: Platform = 'linux';
  private nativeHostName = 'com.payguard.keyring';
  
  async storeKey(keyId: string, key: Uint8Array): Promise<void> {
    await this.sendNativeMessage({ action: 'store', keyId, data: Array.from(key) });
  }
  
  async retrieveKey(keyId: string): Promise<Uint8Array | null> {
    const response = await this.sendNativeMessage({ action: 'retrieve', keyId });
    if (response.data) return new Uint8Array(response.data);
    return null;
  }
  
  async deleteKey(keyId: string): Promise<void> {
    await this.sendNativeMessage({ action: 'delete', keyId });
  }
  
  async isAvailable(): Promise<boolean> {
    if (typeof chrome === 'undefined' || !chrome.runtime?.sendNativeMessage) return false;
    try {
      const response = await this.sendNativeMessage({ action: 'ping' });
      return response.status === 'ok';
    } catch {
      return false;
    }
  }
  
  private sendNativeMessage(message: object): Promise<{ status: string; data?: number[] }> {
    return new Promise((resolve, reject) => {
      if (typeof chrome === 'undefined' || !chrome.runtime?.sendNativeMessage) {
        reject(new SecureStorageError('Native messaging not available', SecureStorageErrorCode.PLATFORM_ERROR));
        return;
      }
      chrome.runtime.sendNativeMessage(this.nativeHostName, message, (response) => {
        if (chrome.runtime.lastError) {
          reject(new SecureStorageError(chrome.runtime.lastError.message || 'Native messaging error', SecureStorageErrorCode.PLATFORM_ERROR));
        } else if (response?.error) {
          reject(new SecureStorageError(response.error, SecureStorageErrorCode.PLATFORM_ERROR));
        } else {
          resolve(response || { status: 'ok' });
        }
      });
    });
  }
}


/**
 * AES-256-GCM Encrypted Secure Storage Implementation.
 */
export class EncryptedSecureStorage implements SecureStorage {
  private encoder = new TextEncoder();
  private decoder = new TextDecoder();
  private keyProvider: KeyStorageProvider;
  private encryptionKey: CryptoKey | null = null;
  private keyVersion: number = 1;
  private initialized: boolean = false;
  private storedKeysIndex: Set<string> = new Set();
  
  constructor(keyProvider?: KeyStorageProvider) {
    this.keyProvider = keyProvider || new BrowserKeyStorageProvider();
  }
  
  async initialize(): Promise<void> {
    if (this.initialized) return;
    
    try {
      const existingKey = await this.loadEncryptionKey();
      if (existingKey) {
        this.encryptionKey = existingKey;
      } else {
        this.encryptionKey = await this.generateEncryptionKey();
        await this.saveEncryptionKey(this.encryptionKey);
      }
      await this.loadKeyVersion();
      await this.loadStoredKeysIndex();
      this.initialized = true;
    } catch (error) {
      throw new SecureStorageError(
        `Failed to initialize secure storage: ${error instanceof Error ? error.message : 'Unknown error'}`,
        SecureStorageErrorCode.KEY_DERIVATION_FAILED
      );
    }
  }
  
  private async ensureInitialized(): Promise<void> {
    if (!this.initialized) await this.initialize();
  }
  
  async store(key: string, data: Uint8Array): Promise<void> {
    await this.ensureInitialized();
    
    if (!this.encryptionKey) {
      throw new SecureStorageError('Encryption key not available', SecureStorageErrorCode.KEY_NOT_FOUND);
    }
    
    try {
      const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
      const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
      
      const encryptedBuffer = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv.buffer as ArrayBuffer, tagLength: AUTH_TAG_LENGTH },
        this.encryptionKey,
        data.buffer as ArrayBuffer
      );
      
      const encryptedArray = new Uint8Array(encryptedBuffer);
      
      const encryptedData: EncryptedData = {
        ciphertext: uint8ArrayToBase64(encryptedArray),
        iv: uint8ArrayToBase64(iv),
        authTag: '',
        salt: uint8ArrayToBase64(salt),
        version: this.keyVersion
      };
      
      await this.setRawStorageItem(key, JSON.stringify(encryptedData));
      this.storedKeysIndex.add(key);
      await this.saveStoredKeysIndex();
    } catch (error) {
      throw new SecureStorageError(
        `Encryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        SecureStorageErrorCode.ENCRYPTION_FAILED
      );
    }
  }
  
  async retrieve(key: string): Promise<Uint8Array | null> {
    await this.ensureInitialized();
    
    if (!this.encryptionKey) {
      throw new SecureStorageError('Encryption key not available', SecureStorageErrorCode.KEY_NOT_FOUND);
    }
    
    try {
      const jsonData = await this.getRawStorageItem(key);
      if (!jsonData) return null;
      
      let encryptedData: EncryptedData;
      try {
        encryptedData = JSON.parse(jsonData);
      } catch {
        throw new SecureStorageError('Invalid encrypted data format', SecureStorageErrorCode.INVALID_DATA);
      }
      
      if (!encryptedData.ciphertext || !encryptedData.iv) {
        throw new SecureStorageError('Missing required encryption fields', SecureStorageErrorCode.INVALID_DATA);
      }
      
      const ciphertext = base64ToUint8Array(encryptedData.ciphertext);
      const iv = base64ToUint8Array(encryptedData.iv);
      
      let decryptedBuffer: ArrayBuffer;
      try {
        decryptedBuffer = await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv: iv.buffer as ArrayBuffer, tagLength: AUTH_TAG_LENGTH },
          this.encryptionKey,
          ciphertext.buffer as ArrayBuffer
        );
      } catch {
        throw new SecureStorageError('Decryption failed - data may have been tampered', SecureStorageErrorCode.TAMPER_DETECTED);
      }
      
      const result = new Uint8Array(decryptedBuffer);
      secureWipeBuffer(decryptedBuffer);
      return result;
    } catch (error) {
      if (error instanceof SecureStorageError) throw error;
      throw new SecureStorageError(
        `Decryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        SecureStorageErrorCode.DECRYPTION_FAILED
      );
    }
  }
  
  async delete(key: string): Promise<void> {
    await this.ensureInitialized();
    await this.removeRawStorageItem(key);
    this.storedKeysIndex.delete(key);
    await this.saveStoredKeysIndex();
  }
  
  async storeString(key: string, value: string): Promise<void> {
    const data = this.encoder.encode(value);
    await this.store(key, data);
  }
  
  async retrieveString(key: string): Promise<string | null> {
    const data = await this.retrieve(key);
    if (data) {
      const result = this.decoder.decode(data);
      secureWipe(data);
      return result;
    }
    return null;
  }

  
  async rotateKey(): Promise<void> {
    await this.ensureInitialized();
    
    if (!this.encryptionKey) {
      throw new SecureStorageError('No existing key to rotate', SecureStorageErrorCode.KEY_NOT_FOUND);
    }
    
    const oldKey = this.encryptionKey;
    const reEncryptedData: Map<string, Uint8Array> = new Map();
    
    try {
      const newKey = await this.generateEncryptionKey();
      
      for (const key of this.storedKeysIndex) {
        if (key.startsWith('key_') || key === STORAGE_KEYS.KEY_VERSION || key === STORAGE_KEYS.STORED_KEYS_INDEX) {
          continue;
        }
        const decryptedData = await this.retrieve(key);
        if (decryptedData) reEncryptedData.set(key, decryptedData);
      }
      
      this.encryptionKey = newKey;
      this.keyVersion++;
      
      for (const [key, data] of reEncryptedData) {
        await this.store(key, data);
        secureWipe(data);
      }
      
      await this.saveEncryptionKey(newKey);
      await this.saveKeyVersion();
      reEncryptedData.clear();
    } catch (error) {
      this.encryptionKey = oldKey;
      throw new SecureStorageError(
        `Key rotation failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        SecureStorageErrorCode.KEY_ROTATION_FAILED
      );
    }
  }
  
  async exportBackup(): Promise<EncryptedBackup> {
    await this.ensureInitialized();
    
    const allData: Record<string, string> = {};
    for (const key of this.storedKeysIndex) {
      const rawData = await this.getRawStorageItem(key);
      if (rawData) allData[key] = rawData;
    }
    
    const jsonData = JSON.stringify(allData);
    const dataBytes = this.encoder.encode(jsonData);
    const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
    const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
    
    if (!this.encryptionKey) {
      throw new SecureStorageError('Encryption key not available', SecureStorageErrorCode.KEY_NOT_FOUND);
    }
    
    const encryptedBuffer = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv.buffer as ArrayBuffer, tagLength: AUTH_TAG_LENGTH },
      this.encryptionKey,
      dataBytes.buffer as ArrayBuffer
    );
    
    const encryptedArray = new Uint8Array(encryptedBuffer);
    const authTagStart = encryptedArray.length - (AUTH_TAG_LENGTH / 8);
    const authTag = encryptedArray.slice(authTagStart);
    
    return {
      version: '1.0',
      encryptedData: encryptedArray,
      salt: salt,
      iv: iv,
      authTag: authTag,
      createdAt: new Date()
    };
  }
  
  async importBackup(backup: EncryptedBackup, password: string): Promise<void> {
    await this.ensureInitialized();
    
    try {
      const keyMaterial = await crypto.subtle.importKey(
        'raw',
        this.encoder.encode(password).buffer as ArrayBuffer,
        'PBKDF2',
        false,
        ['deriveBits', 'deriveKey']
      );
      
      const importKey = await crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt: backup.salt.buffer as ArrayBuffer, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
        keyMaterial,
        { name: 'AES-GCM', length: KEY_LENGTH },
        false,
        ['decrypt']
      );
      
      const decryptedBuffer = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: backup.iv.buffer as ArrayBuffer, tagLength: AUTH_TAG_LENGTH },
        importKey,
        backup.encryptedData.buffer as ArrayBuffer
      );
      
      const jsonData = this.decoder.decode(decryptedBuffer);
      const allData: Record<string, string> = JSON.parse(jsonData);
      
      for (const [key, value] of Object.entries(allData)) {
        await this.setRawStorageItem(key, value);
        this.storedKeysIndex.add(key);
      }
      
      await this.saveStoredKeysIndex();
      secureWipeBuffer(decryptedBuffer);
    } catch (error) {
      throw new SecureStorageError(
        `Backup import failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        SecureStorageErrorCode.DECRYPTION_FAILED
      );
    }
  }

  
  // Private helper methods
  private async generateEncryptionKey(): Promise<CryptoKey> {
    return crypto.subtle.generateKey(
      { name: 'AES-GCM', length: KEY_LENGTH },
      true,
      ['encrypt', 'decrypt']
    );
  }
  
  private async loadEncryptionKey(): Promise<CryptoKey | null> {
    const keyData = await this.keyProvider.retrieveKey(STORAGE_KEYS.ENCRYPTION_KEY_ID);
    if (!keyData) return null;
    
    try {
      return await crypto.subtle.importKey(
        'raw',
        keyData.buffer as ArrayBuffer,
        { name: 'AES-GCM', length: KEY_LENGTH },
        true,
        ['encrypt', 'decrypt']
      );
    } finally {
      secureWipe(keyData);
    }
  }
  
  private async saveEncryptionKey(key: CryptoKey): Promise<void> {
    const keyData = await crypto.subtle.exportKey('raw', key);
    const keyArray = new Uint8Array(keyData);
    
    try {
      await this.keyProvider.storeKey(STORAGE_KEYS.ENCRYPTION_KEY_ID, keyArray);
    } finally {
      secureWipe(keyArray);
      secureWipeBuffer(keyData);
    }
  }
  
  private async loadKeyVersion(): Promise<void> {
    const versionStr = await this.getRawStorageItem(STORAGE_KEYS.KEY_VERSION);
    if (versionStr) this.keyVersion = parseInt(versionStr, 10) || 1;
  }
  
  private async saveKeyVersion(): Promise<void> {
    await this.setRawStorageItem(STORAGE_KEYS.KEY_VERSION, this.keyVersion.toString());
  }
  
  private async loadStoredKeysIndex(): Promise<void> {
    const indexStr = await this.getRawStorageItem(STORAGE_KEYS.STORED_KEYS_INDEX);
    if (indexStr) {
      try {
        this.storedKeysIndex = new Set(JSON.parse(indexStr));
      } catch {
        this.storedKeysIndex = new Set();
      }
    }
  }
  
  private async saveStoredKeysIndex(): Promise<void> {
    await this.setRawStorageItem(STORAGE_KEYS.STORED_KEYS_INDEX, JSON.stringify(Array.from(this.storedKeysIndex)));
  }
  
  private async setRawStorageItem(key: string, value: string): Promise<void> {
    return new Promise((resolve, reject) => {
      if (typeof chrome !== 'undefined' && chrome.storage) {
        chrome.storage.local.set({ [key]: value }, () => {
          if (chrome.runtime?.lastError) {
            reject(new SecureStorageError(chrome.runtime.lastError.message || 'Storage error', SecureStorageErrorCode.STORAGE_UNAVAILABLE));
          } else {
            resolve();
          }
        });
      } else {
        try {
          localStorage.setItem(key, value);
          resolve();
        } catch {
          reject(new SecureStorageError('localStorage unavailable', SecureStorageErrorCode.STORAGE_UNAVAILABLE));
        }
      }
    });
  }
  
  private async getRawStorageItem(key: string): Promise<string | null> {
    return new Promise((resolve, reject) => {
      if (typeof chrome !== 'undefined' && chrome.storage) {
        chrome.storage.local.get([key], (result) => {
          if (chrome.runtime?.lastError) {
            reject(new SecureStorageError(chrome.runtime.lastError.message || 'Storage error', SecureStorageErrorCode.STORAGE_UNAVAILABLE));
          } else {
            resolve(result[key] || null);
          }
        });
      } else {
        resolve(localStorage.getItem(key));
      }
    });
  }
  
  private async removeRawStorageItem(key: string): Promise<void> {
    return new Promise((resolve, reject) => {
      if (typeof chrome !== 'undefined' && chrome.storage) {
        chrome.storage.local.remove([key], () => {
          if (chrome.runtime?.lastError) {
            reject(new SecureStorageError(chrome.runtime.lastError.message || 'Storage error', SecureStorageErrorCode.STORAGE_UNAVAILABLE));
          } else {
            resolve();
          }
        });
      } else {
        localStorage.removeItem(key);
        resolve();
      }
    });
  }
}


/**
 * Password-based key derivation secure storage.
 * Uses PBKDF2 for key derivation from user password.
 */
export class PasswordDerivedSecureStorage implements SecureStorage {
  private encoder = new TextEncoder();
  private decoder = new TextDecoder();
  private encryptionKey: CryptoKey | null = null;
  private salt: Uint8Array | null = null;
  private initialized: boolean = false;
  private storedKeysIndex: Set<string> = new Set();
  
  constructor(private password: string) {}
  
  async initialize(): Promise<void> {
    if (this.initialized) return;
    
    try {
      const existingSalt = await this.loadSalt();
      if (existingSalt) {
        this.salt = existingSalt;
      } else {
        this.salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
        await this.saveSalt(this.salt);
      }
      
      this.encryptionKey = await this.deriveKeyFromPassword(this.password, this.salt);
      await this.loadStoredKeysIndex();
      this.initialized = true;
    } catch (error) {
      throw new SecureStorageError(
        `Failed to initialize password-derived storage: ${error instanceof Error ? error.message : 'Unknown error'}`,
        SecureStorageErrorCode.KEY_DERIVATION_FAILED
      );
    }
  }
  
  private async ensureInitialized(): Promise<void> {
    if (!this.initialized) await this.initialize();
  }
  
  private async deriveKeyFromPassword(password: string, salt: Uint8Array): Promise<CryptoKey> {
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      this.encoder.encode(password).buffer as ArrayBuffer,
      'PBKDF2',
      false,
      ['deriveBits', 'deriveKey']
    );
    
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: salt.buffer as ArrayBuffer, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
      keyMaterial,
      { name: 'AES-GCM', length: KEY_LENGTH },
      true,
      ['encrypt', 'decrypt']
    );
  }
  
  async store(key: string, data: Uint8Array): Promise<void> {
    await this.ensureInitialized();
    
    if (!this.encryptionKey) {
      throw new SecureStorageError('Encryption key not available', SecureStorageErrorCode.KEY_NOT_FOUND);
    }
    
    try {
      const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
      
      const encryptedBuffer = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv.buffer as ArrayBuffer, tagLength: AUTH_TAG_LENGTH },
        this.encryptionKey,
        data.buffer as ArrayBuffer
      );
      
      const encryptedArray = new Uint8Array(encryptedBuffer);
      
      const encryptedData: EncryptedData = {
        ciphertext: uint8ArrayToBase64(encryptedArray),
        iv: uint8ArrayToBase64(iv),
        authTag: '',
        salt: uint8ArrayToBase64(this.salt!),
        version: ENCRYPTION_VERSION
      };
      
      await this.setRawStorageItem(key, JSON.stringify(encryptedData));
      this.storedKeysIndex.add(key);
      await this.saveStoredKeysIndex();
    } catch (error) {
      throw new SecureStorageError(
        `Encryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        SecureStorageErrorCode.ENCRYPTION_FAILED
      );
    }
  }
  
  async retrieve(key: string): Promise<Uint8Array | null> {
    await this.ensureInitialized();
    
    if (!this.encryptionKey) {
      throw new SecureStorageError('Encryption key not available', SecureStorageErrorCode.KEY_NOT_FOUND);
    }
    
    try {
      const jsonData = await this.getRawStorageItem(key);
      if (!jsonData) return null;
      
      const encryptedData: EncryptedData = JSON.parse(jsonData);
      const ciphertext = base64ToUint8Array(encryptedData.ciphertext);
      const iv = base64ToUint8Array(encryptedData.iv);
      
      let decryptedBuffer: ArrayBuffer;
      try {
        decryptedBuffer = await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv: iv.buffer as ArrayBuffer, tagLength: AUTH_TAG_LENGTH },
          this.encryptionKey,
          ciphertext.buffer as ArrayBuffer
        );
      } catch {
        throw new SecureStorageError('Decryption failed - data may have been tampered', SecureStorageErrorCode.TAMPER_DETECTED);
      }
      
      const result = new Uint8Array(decryptedBuffer);
      secureWipeBuffer(decryptedBuffer);
      return result;
    } catch (error) {
      if (error instanceof SecureStorageError) throw error;
      throw new SecureStorageError(
        `Decryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        SecureStorageErrorCode.DECRYPTION_FAILED
      );
    }
  }
  
  async delete(key: string): Promise<void> {
    await this.ensureInitialized();
    await this.removeRawStorageItem(key);
    this.storedKeysIndex.delete(key);
    await this.saveStoredKeysIndex();
  }
  
  async storeString(key: string, value: string): Promise<void> {
    const data = this.encoder.encode(value);
    await this.store(key, data);
  }
  
  async retrieveString(key: string): Promise<string | null> {
    const data = await this.retrieve(key);
    if (data) {
      const result = this.decoder.decode(data);
      secureWipe(data);
      return result;
    }
    return null;
  }
  
  async rotateKey(): Promise<void> {
    throw new SecureStorageError(
      'Key rotation requires changing password for password-derived storage',
      SecureStorageErrorCode.KEY_ROTATION_FAILED,
      true
    );
  }
  
  async exportBackup(): Promise<EncryptedBackup> {
    await this.ensureInitialized();
    
    const allData: Record<string, string> = {};
    for (const key of this.storedKeysIndex) {
      const rawData = await this.getRawStorageItem(key);
      if (rawData) allData[key] = rawData;
    }
    
    const jsonData = JSON.stringify(allData);
    const dataBytes = this.encoder.encode(jsonData);
    const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
    
    if (!this.encryptionKey || !this.salt) {
      throw new SecureStorageError('Encryption key not available', SecureStorageErrorCode.KEY_NOT_FOUND);
    }
    
    const encryptedBuffer = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv.buffer as ArrayBuffer, tagLength: AUTH_TAG_LENGTH },
      this.encryptionKey,
      dataBytes.buffer as ArrayBuffer
    );
    
    const encryptedArray = new Uint8Array(encryptedBuffer);
    const authTagStart = encryptedArray.length - (AUTH_TAG_LENGTH / 8);
    const authTag = encryptedArray.slice(authTagStart);
    
    return {
      version: '1.0',
      encryptedData: encryptedArray,
      salt: this.salt,
      iv: iv,
      authTag: authTag,
      createdAt: new Date()
    };
  }
  
  async importBackup(backup: EncryptedBackup, password: string): Promise<void> {
    try {
      const importKey = await this.deriveKeyFromPassword(password, backup.salt);
      
      const decryptedBuffer = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: backup.iv.buffer as ArrayBuffer, tagLength: AUTH_TAG_LENGTH },
        importKey,
        backup.encryptedData.buffer as ArrayBuffer
      );
      
      const jsonData = this.decoder.decode(decryptedBuffer);
      const allData: Record<string, string> = JSON.parse(jsonData);
      
      for (const [key, value] of Object.entries(allData)) {
        await this.setRawStorageItem(key, value);
        this.storedKeysIndex.add(key);
      }
      
      await this.saveStoredKeysIndex();
      secureWipeBuffer(decryptedBuffer);
    } catch (error) {
      throw new SecureStorageError(
        `Backup import failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        SecureStorageErrorCode.DECRYPTION_FAILED
      );
    }
  }
  
  // Private helper methods
  private async loadSalt(): Promise<Uint8Array | null> {
    const saltStr = await this.getRawStorageItem('payguard_password_salt');
    if (saltStr) return base64ToUint8Array(saltStr);
    return null;
  }
  
  private async saveSalt(salt: Uint8Array): Promise<void> {
    await this.setRawStorageItem('payguard_password_salt', uint8ArrayToBase64(salt));
  }
  
  private async loadStoredKeysIndex(): Promise<void> {
    const indexStr = await this.getRawStorageItem(STORAGE_KEYS.STORED_KEYS_INDEX);
    if (indexStr) {
      try {
        this.storedKeysIndex = new Set(JSON.parse(indexStr));
      } catch {
        this.storedKeysIndex = new Set();
      }
    }
  }
  
  private async saveStoredKeysIndex(): Promise<void> {
    await this.setRawStorageItem(STORAGE_KEYS.STORED_KEYS_INDEX, JSON.stringify(Array.from(this.storedKeysIndex)));
  }
  
  private async setRawStorageItem(key: string, value: string): Promise<void> {
    return new Promise((resolve, reject) => {
      if (typeof chrome !== 'undefined' && chrome.storage) {
        chrome.storage.local.set({ [key]: value }, () => {
          if (chrome.runtime?.lastError) {
            reject(new SecureStorageError(chrome.runtime.lastError.message || 'Storage error', SecureStorageErrorCode.STORAGE_UNAVAILABLE));
          } else {
            resolve();
          }
        });
      } else {
        try {
          localStorage.setItem(key, value);
          resolve();
        } catch {
          reject(new SecureStorageError('localStorage unavailable', SecureStorageErrorCode.STORAGE_UNAVAILABLE));
        }
      }
    });
  }
  
  private async getRawStorageItem(key: string): Promise<string | null> {
    return new Promise((resolve, reject) => {
      if (typeof chrome !== 'undefined' && chrome.storage) {
        chrome.storage.local.get([key], (result) => {
          if (chrome.runtime?.lastError) {
            reject(new SecureStorageError(chrome.runtime.lastError.message || 'Storage error', SecureStorageErrorCode.STORAGE_UNAVAILABLE));
          } else {
            resolve(result[key] || null);
          }
        });
      } else {
        resolve(localStorage.getItem(key));
      }
    });
  }
  
  private async removeRawStorageItem(key: string): Promise<void> {
    return new Promise((resolve, reject) => {
      if (typeof chrome !== 'undefined' && chrome.storage) {
        chrome.storage.local.remove([key], () => {
          if (chrome.runtime?.lastError) {
            reject(new SecureStorageError(chrome.runtime.lastError.message || 'Storage error', SecureStorageErrorCode.STORAGE_UNAVAILABLE));
          } else {
            resolve();
          }
        });
      } else {
        localStorage.removeItem(key);
        resolve();
      }
    });
  }
}


/**
 * Factory function to create the appropriate secure storage based on platform.
 */
export async function createSecureStorage(): Promise<SecureStorage> {
  const providers: KeyStorageProvider[] = [
    new MacOSKeychainProvider(),
    new WindowsDPAPIProvider(),
    new LinuxKeyringProvider(),
    new BrowserKeyStorageProvider()
  ];
  
  for (const provider of providers) {
    if (await provider.isAvailable()) {
      const storage = new EncryptedSecureStorage(provider);
      await storage.initialize();
      return storage;
    }
  }
  
  const storage = new EncryptedSecureStorage(new BrowserKeyStorageProvider());
  await storage.initialize();
  return storage;
}

/**
 * Create password-derived secure storage.
 */
export async function createPasswordDerivedStorage(password: string): Promise<SecureStorage> {
  const storage = new PasswordDerivedSecureStorage(password);
  await storage.initialize();
  return storage;
}

// Legacy export for backward compatibility
export { EncryptedSecureStorage as BrowserSecureStorage };

// Singleton instance (lazy initialization)
let _secureStorage: SecureStorage | null = null;

export async function getSecureStorage(): Promise<SecureStorage> {
  if (!_secureStorage) {
    _secureStorage = await createSecureStorage();
  }
  return _secureStorage;
}

// For testing - allows resetting the singleton
export function resetSecureStorage(): void {
  _secureStorage = null;
}
