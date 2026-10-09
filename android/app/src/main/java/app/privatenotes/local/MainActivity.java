package app.privatenotes.local;

import android.os.Bundle;
import android.os.Build;
import android.view.View;
import android.view.WindowManager;
import android.webkit.WebView;

import com.getcapacitor.BridgeActivity;

public class MainActivity extends BridgeActivity {
  @Override
  public void onCreate(Bundle savedInstanceState) {
    registerPlugin(NativeVaultGuard.class);
    super.onCreate(savedInstanceState);
    WebView.setWebContentsDebuggingEnabled(false);
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
      getWindow().setHideOverlayWindows(true);
    }
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
      getWindow().getDecorView().setImportantForAutofill(
        View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
      );
    }
    getWindow().setFlags(
      WindowManager.LayoutParams.FLAG_SECURE,
      WindowManager.LayoutParams.FLAG_SECURE
    );
  }
}
