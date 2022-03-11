package com.wyy;

import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;
import androidx.appcompat.app.AppCompatActivity;
import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import androidx.core.content.ContextCompat;

import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.provider.Settings;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;
import android.view.View;
import android.widget.Toast;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.concurrent.Executor;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class MainActivity extends AppCompatActivity {
    private static final String TAG = "MainActivity";

    private Context mContext;

    private Executor executor;
    private BiometricPrompt biometricPrompt;
    private BiometricPrompt.PromptInfo promptInfo;

    private boolean mIsEncryptMode = false;
    // 加密信息
    private byte[] encryptedInfo = new byte[0];

    // 向量 加密成功后获取的
    private byte[] ivByte;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        mContext = this;


        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                    // 仅使用生物识别凭据进行身份验证
                    generateSecretKey(new KeyGenParameterSpec.Builder(
                            KEY_NAME,
                            KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                            .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                            .setUserAuthenticationRequired(true)
                            // Invalidate the keys if the user has registered a new biometric
                            // credential, such as a new fingerprint. Can call this method only
                            // on Android 7.0 (API level 24) or higher. The variable
                            // "invalidatedByBiometricEnrollment" is true by default.
                            .setInvalidatedByBiometricEnrollment(true)
                            .build());
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        findViewById(R.id.btn1).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                checkBiometric();
            }
        });

        executor = ContextCompat.getMainExecutor(this);
        biometricPrompt = new BiometricPrompt(MainActivity.this, executor, new BiometricPrompt.AuthenticationCallback() {
            @Override
            public void onAuthenticationError(int errorCode,
                                              @NonNull CharSequence errString) {
                super.onAuthenticationError(errorCode, errString);
                Toast.makeText(getApplicationContext(),
                        "Authentication error: " + errString, Toast.LENGTH_SHORT)
                        .show();
            }

            @Override
            public void onAuthenticationSucceeded(
                    @NonNull BiometricPrompt.AuthenticationResult result) {
                super.onAuthenticationSucceeded(result);
                Toast.makeText(getApplicationContext(), "认证成功", Toast.LENGTH_SHORT).show();
                // 在生物识别身份验证回调中，使用密钥加密敏感信息：

                    try {
                        if (mIsEncryptMode) {
                            encryptedInfo = result.getCryptoObject().getCipher().doFinal(
                                    "123456".getBytes(Charset.defaultCharset()));

                            ivByte = result.getCryptoObject().getCipher().getIV();
                        } else {
                            byte[] decryptInfo = result.getCryptoObject().getCipher().doFinal(encryptedInfo);
                            Log.d(TAG, "onAuthenticationSucceeded: " + new String(decryptInfo));
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                    Log.d("MY_APP_TAG", "Encrypted information: " + Arrays.toString(encryptedInfo));




            }

            @Override
            public void onAuthenticationFailed() {
                super.onAuthenticationFailed();
                Toast.makeText(getApplicationContext(), "认证失败", Toast.LENGTH_SHORT).show();
            }
        });



        promptInfo = new BiometricPrompt.PromptInfo.Builder()
                .setTitle(getApplicationName(mContext) + "登录")
                .setSubtitle("请验证已有手机指纹")
                .setNegativeButtonText("使用密码验证")
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                .build();


        // Prompt appears when user clicks "Log in".
        // Consider integrating with the keystore to unlock cryptographic operations,
        // if needed by your app.
//
        findViewById(R.id.btn2).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
//                biometricPrompt.authenticate(promptInfo);
                // 启动一个包含密码的生物识别身份验证工作流程
                mIsEncryptMode = true;
                try {
                    Cipher cipher = getCipher();
                    SecretKey secretKey = getSecretKey();
                    cipher.init(Cipher.ENCRYPT_MODE, secretKey);
                    biometricPrompt.authenticate(promptInfo, new BiometricPrompt.CryptoObject(cipher));
                } catch (Exception e) {
                    e.printStackTrace();
                }

            }
        });

        findViewById(R.id.btn3).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
//                biometricPrompt.authenticate(promptInfo);
                // 启动一个包含密码的生物识别身份验证工作流程
                mIsEncryptMode = false;
                try {
                    Cipher cipher = getCipher();
                    SecretKey secretKey = getSecretKey();
                    IvParameterSpec iv = new IvParameterSpec(ivByte);
                    cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
//                    byte[] decryptInfo = cipher.doFinal(encryptedInfo);
//                    Log.d(TAG, "onAuthenticationSucceeded: " + Arrays.toString(decryptInfo));
                    biometricPrompt.authenticate(promptInfo, new BiometricPrompt.CryptoObject(cipher));
                } catch (Exception e) {
                    e.printStackTrace();
                }

            }
        });

    }

    /**
     * 获取程序名称
     *
     * @param context
     * @return
     */
    public static String getApplicationName(Context context) {
        PackageManager packageManager = null;
        ApplicationInfo applicationInfo;
        try {
            packageManager = context.getApplicationContext().getPackageManager();
            applicationInfo = packageManager.getApplicationInfo(context.getPackageName(), 0);
        } catch (PackageManager.NameNotFoundException e) {
            applicationInfo = null;
        }
        String applicationName = (String) packageManager.getApplicationLabel(applicationInfo);
        return applicationName;
    }


    /**
     * 检测是否支持生物认证
     */
    private void checkBiometric() {
        BiometricManager biometricManager = BiometricManager.from(mContext);
        switch (biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)) {
            case BiometricManager.BIOMETRIC_SUCCESS:
                Log.d("MY_APP_TAG", "App can authenticate using biometrics.");
                Toast.makeText(mContext, "支持", Toast.LENGTH_SHORT).show();
                break;
            case BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE:
                Log.e("MY_APP_TAG", "No biometric features available on this device.");
                break;
            case BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE:
                Log.e("MY_APP_TAG", "Biometric features are currently unavailable.");
                break;
            case BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED:
                // Prompts the user to create credentials that your app accepts.
                Toast.makeText(mContext, "不支持", Toast.LENGTH_SHORT).show();
                try {
                    final Intent enrollIntent = new Intent(Settings.ACTION_BIOMETRIC_ENROLL);
                    enrollIntent.putExtra(Settings.EXTRA_BIOMETRIC_AUTHENTICATORS_ALLOWED,
                            BiometricManager.Authenticators.BIOMETRIC_STRONG | BiometricManager.Authenticators.DEVICE_CREDENTIAL);
                    startActivityForResult(enrollIntent, 1);
                } catch (Exception e) {

                }
                break;
        }
    }


    private static final String KEY_NAME = "com.ocsok.simple.shiliutong";

    @RequiresApi(api = Build.VERSION_CODES.M)
    private void generateSecretKey(KeyGenParameterSpec keyGenParameterSpec) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        keyGenerator.init(keyGenParameterSpec);
        keyGenerator.generateKey();
    }

    private SecretKey getSecretKey() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, UnrecoverableKeyException {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");

        // Before the keystore can be accessed, it must be loaded.
        keyStore.load(null);
        return ((SecretKey)keyStore.getKey(KEY_NAME, null));
    }

    private Cipher getCipher() throws NoSuchPaddingException, NoSuchAlgorithmException {
        return Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/"
                + KeyProperties.BLOCK_MODE_CBC + "/"
                + KeyProperties.ENCRYPTION_PADDING_PKCS7);
    }

}