package app.privatenotes.local;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStore;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

@CapacitorPlugin(name = "NativeVaultGuard")
public class NativeVaultGuard extends Plugin {
  private static final String KEY_ALIAS = "app.privatenotes.local.failed-attempt-state.v1";
  private static final String PREFERENCES = "private_notes_vault_guard";
  private static final String STATE_KEY = "encrypted_failed_attempt_state";
  private static final String TRANSFORMATION = "AES/GCM/NoPadding";
  private static final int IV_LENGTH_BYTES = 12;
  private static final int TAG_LENGTH_BITS = 128;
  private static final int MAX_STATE_LENGTH = 2048;

  @PluginMethod
  public void getAttemptState(PluginCall call) {
    try {
      String stored = getPreferences().getString(STATE_KEY, null);
      String data = stored == null ? null : decrypt(stored);
      JSObject result = new JSObject();
      result.put("data", data == null ? JSObject.NULL : data);
      call.resolve(result);
    } catch (Exception error) {
      call.reject("Secure failed-attempt state could not be read.", error);
    }
  }

  @PluginMethod
  public void setAttemptState(PluginCall call) {
    String data = call.getString("data");
    if (data == null || data.isEmpty() || data.length() > MAX_STATE_LENGTH) {
      call.reject("Secure failed-attempt state is invalid.");
      return;
    }

    try {
      String encrypted = encrypt(data);
      boolean saved = getPreferences().edit().putString(STATE_KEY, encrypted).commit();
      if (!saved) {
        throw new IOException("The operating system did not confirm the secure state write.");
      }
      call.resolve();
    } catch (Exception error) {
      call.reject("Secure failed-attempt state could not be saved.", error);
    }
  }

  @PluginMethod
  public void removeAttemptState(PluginCall call) {
    try {
      boolean removed = getPreferences().edit().remove(STATE_KEY).commit();
      if (!removed) {
        throw new IOException("The operating system did not confirm the secure state removal.");
      }
      KeyStore keyStore = getKeyStore();
      if (keyStore.containsAlias(KEY_ALIAS)) {
        keyStore.deleteEntry(KEY_ALIAS);
      }
      call.resolve();
    } catch (Exception error) {
      call.reject("Secure failed-attempt state could not be removed.", error);
    }
  }

  private SharedPreferences getPreferences() {
    return getContext().getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE);
  }

  private String encrypt(String data) throws GeneralSecurityException, IOException {
    Cipher cipher = Cipher.getInstance(TRANSFORMATION);
    cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey());
    cipher.updateAAD(KEY_ALIAS.getBytes(StandardCharsets.UTF_8));
    byte[] encrypted = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
    byte[] iv = cipher.getIV();
    if (iv == null || iv.length != IV_LENGTH_BYTES) {
      throw new GeneralSecurityException("The platform returned an invalid AES-GCM nonce.");
    }
    ByteBuffer payload = ByteBuffer.allocate(iv.length + encrypted.length);
    payload.put(iv);
    payload.put(encrypted);
    return Base64.encodeToString(payload.array(), Base64.NO_WRAP);
  }

  private String decrypt(String encoded) throws GeneralSecurityException, IOException {
    byte[] payload = Base64.decode(encoded, Base64.NO_WRAP);
    if (payload.length <= IV_LENGTH_BYTES + TAG_LENGTH_BITS / 8) {
      throw new GeneralSecurityException("Secure failed-attempt state is truncated.");
    }

    byte[] iv = new byte[IV_LENGTH_BYTES];
    byte[] encrypted = new byte[payload.length - IV_LENGTH_BYTES];
    System.arraycopy(payload, 0, iv, 0, iv.length);
    System.arraycopy(payload, iv.length, encrypted, 0, encrypted.length);

    Cipher cipher = Cipher.getInstance(TRANSFORMATION);
    cipher.init(Cipher.DECRYPT_MODE, getExistingKey(), new GCMParameterSpec(TAG_LENGTH_BITS, iv));
    cipher.updateAAD(KEY_ALIAS.getBytes(StandardCharsets.UTF_8));
    return new String(cipher.doFinal(encrypted), StandardCharsets.UTF_8);
  }

  private SecretKey getOrCreateKey() throws GeneralSecurityException, IOException {
    KeyStore keyStore = getKeyStore();
    if (keyStore.containsAlias(KEY_ALIAS)) {
      return getExistingKey();
    }

    KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
    KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
      KEY_ALIAS,
      KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT
    )
      .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
      .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
      .setKeySize(256)
      .setRandomizedEncryptionRequired(true)
      .build();
    generator.init(spec);
    return generator.generateKey();
  }

  private SecretKey getExistingKey() throws GeneralSecurityException, IOException {
    KeyStore keyStore = getKeyStore();
    if (!keyStore.containsAlias(KEY_ALIAS)) {
      throw new GeneralSecurityException("The device-bound secure state key is missing.");
    }
    KeyStore.SecretKeyEntry entry = (KeyStore.SecretKeyEntry) keyStore.getEntry(KEY_ALIAS, null);
    if (entry == null) {
      throw new GeneralSecurityException("The device-bound secure state key is unavailable.");
    }
    return entry.getSecretKey();
  }

  private KeyStore getKeyStore() throws GeneralSecurityException, IOException {
    KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
    keyStore.load(null);
    return keyStore;
  }
}
