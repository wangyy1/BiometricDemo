package com.wyy;

import android.content.Context;
import android.os.Bundle;
import android.util.Log;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import androidx.core.content.ContextCompat;

import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.concurrent.Executor;

/**
 * 没有处理完，只是用来测试的
 */
public class DialogActivity extends AppCompatActivity {

    private Executor executor;
    private BiometricPrompt biometricPrompt;
    private BiometricPrompt.PromptInfo promptInfo;

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_dialog);


        executor = ContextCompat.getMainExecutor(this);
        biometricPrompt = new BiometricPrompt(DialogActivity.this, executor, new BiometricPrompt.AuthenticationCallback() {
            @Override
            public void onAuthenticationError(int errorCode,
                                              @NonNull CharSequence errString) {
                super.onAuthenticationError(errorCode, errString);
                Toast.makeText(getApplicationContext(),
                        "Authentication error: " + errString, Toast.LENGTH_SHORT)
                        .show();
                finish();
            }

            @Override
            public void onAuthenticationSucceeded(
                    @NonNull BiometricPrompt.AuthenticationResult result) {
                super.onAuthenticationSucceeded(result);
                Toast.makeText(getApplicationContext(), "认证成功", Toast.LENGTH_SHORT).show();
                // 在生物识别身份验证回调中，使用密钥加密敏感信息：
            }

            @Override
            public void onAuthenticationFailed() {
                super.onAuthenticationFailed();
                Toast.makeText(getApplicationContext(), "认证失败", Toast.LENGTH_SHORT).show();
            }
        });



        promptInfo = new BiometricPrompt.PromptInfo.Builder()
                .setTitle("测试登录")
                .setSubtitle("请验证已有手机指纹")
                .setNegativeButtonText("使用密码验证")
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                .build();

        biometricPrompt.authenticate(promptInfo);
    }
}
