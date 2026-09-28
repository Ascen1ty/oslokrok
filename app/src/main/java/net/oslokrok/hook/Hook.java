package net.oslokrok.hook;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Member;
import java.lang.reflect.Modifier;
import java.util.HashSet;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.IXposedHookZygoteInit;
import de.robv.android.xposed.XC_MethodReplacement;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import org.luckypray.dexkit.DexKitBridge;
import org.luckypray.dexkit.query.FindClass;
import org.luckypray.dexkit.query.FindMethod;
import org.luckypray.dexkit.query.matchers.ClassMatcher;
import org.luckypray.dexkit.query.matchers.MethodMatcher;
import org.luckypray.dexkit.query.enums.StringMatchType;
import org.luckypray.dexkit.result.ClassData;
import org.luckypray.dexkit.result.ClassDataList;
import org.luckypray.dexkit.result.MethodData;
import org.luckypray.dexkit.result.MethodDataList;

/**
 * Stops app's on-launch root-detection (RASP) crash by no-opping
 * single upstream emit point of the detection signal flow.
 *
 * The method is resolved dynamically at load via DexKit (structural
 * anchors, not hardcoded names) so it should survive app updates. If
 * DexKit is fails to load, falls back to hardcoded method.
 */
public class Hook implements IXposedHookLoadPackage, IXposedHookZygoteInit {

    private static final String TARGET = "com.paypal.android.p2pmobile";
    private static final String IFACE  = "com.paypal.oslo.core.security.rasp.SignalRaspDetectionDataSource";
    private static final String IMPL   = "com.paypal.oslo.core.security.rasp.RaspDetectionDataSourceImpl";
    private static final String PKG    = "com.paypal.oslo.core.security.rasp";
    private static final String SIGNAL = "signal";
    private static final String ABI    = "arm64-v8a";
    private static final String TAG    = "[oslokrok] ";

    private static boolean nativeLoaded = false;
    private String modulePath;

    @Override
    public void initZygote(IXposedHookZygoteInit.StartupParam startupParam) {
        this.modulePath = startupParam.modulePath;
    }

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) {
        if (!TARGET.equals(lpparam.packageName)) return;
        ClassLoader cl = lpparam.classLoader;

        boolean nativeOk = loadDexKitNative(lpparam);

        Set<Member> targets = new HashSet<>();
        if (nativeOk) {
            DexKitBridge bridge = null;
            try {
                bridge = DexKitBridge.create(cl, true);

                // (A) any 0-arg signal() declared in the rasp.* package
                try {
                    MethodDataList ms = bridge.findMethod(FindMethod.create().matcher(
                            MethodMatcher.create()
                                    .declaredClass(PKG, StringMatchType.Contains)
                                    .name(SIGNAL)
                                    .paramCount(0)));
                    for (MethodData md : ms) {
                        try { targets.add(md.getMethodInstance(cl)); } catch (Throwable ignored) {}
                    }
                } catch (Throwable t) { XposedBridge.log(TAG + "query A failed: " + t); }

                // (B) classes implementing the stable interface -> their signal()
                try {
                    ClassDataList impls = bridge.findClass(FindClass.create().matcher(
                            ClassMatcher.create().addInterface(IFACE)));
                    for (ClassData cd : impls) {
                        try { targets.add(cd.getInstance(cl).getDeclaredMethod(SIGNAL)); }
                        catch (Throwable ignored) {}
                    }
                } catch (Throwable t) { XposedBridge.log(TAG + "query B failed: " + t); }

            } catch (Throwable t) {
                XposedBridge.log(TAG + "DexKit init failed: " + t);
            } finally {
                if (bridge != null) try { bridge.close(); } catch (Throwable ignored) {}
            }
        }

        int hooks = 0;
        for (Member m : targets) {
            if ((m.getModifiers() & Modifier.ABSTRACT) != 0) continue; // skip interface decl
            try {
                XposedBridge.hookMethod(m, XC_MethodReplacement.returnConstant(null));
                hooks++;
                XposedBridge.log(TAG + "hooked (dynamic) " + m);
            } catch (Throwable t) { XposedBridge.log(TAG + "hook failed on " + m + ": " + t); }
        }

        if (hooks == 0) {
            try {
                XposedHelpers.findAndHookMethod(IMPL, cl, SIGNAL,
                        XC_MethodReplacement.returnConstant(null));
                hooks++;
                XposedBridge.log(TAG + "hooked (fallback) " + IMPL + "." + SIGNAL + "()");
            } catch (Throwable t) {
                XposedBridge.log(TAG + "fallback hook failed: " + t);
            }
        }

        XposedBridge.log(TAG + "active on " + TARGET + ", signal hooks=" + hooks
                + (nativeOk ? " (dexkit)" : " (no-dexkit)"));
    }

    /** Load libdexkit.so: try the classloader path, else extract from APK and load by path. */
    private boolean loadDexKitNative(XC_LoadPackage.LoadPackageParam lpparam) {
        if (nativeLoaded) return true;
        try { System.loadLibrary("dexkit"); nativeLoaded = true; return true; }
        catch (Throwable ignored) { /* not on the module classloader's lib path under Vector */ }

        try {
            if (modulePath == null) { XposedBridge.log(TAG + "modulePath unknown; cannot extract .so"); return false; }
            String base = (lpparam.appInfo != null && lpparam.appInfo.dataDir != null)
                    ? lpparam.appInfo.dataDir : "/data/local/tmp";
            File dir = new File(base, ".oslokrok");
            dir.mkdirs();
            File so = new File(dir, "libdexkit.so");

            ZipFile zf = new ZipFile(modulePath);
            try {
                ZipEntry e = zf.getEntry("lib/" + ABI + "/libdexkit.so");
                if (e == null) { XposedBridge.log(TAG + ".so not found in module APK"); return false; }
                if (!so.exists() || so.length() != e.getSize()) {
                    InputStream in = zf.getInputStream(e);
                    OutputStream out = new FileOutputStream(so);
                    try {
                        byte[] buf = new byte[8192]; int n;
                        while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
                    } finally { out.close(); in.close(); }
                    so.setReadable(true, false);
                    so.setExecutable(true, false);
                }
            } finally { zf.close(); }

            System.load(so.getAbsolutePath());
            nativeLoaded = true;
            XposedBridge.log(TAG + "loaded libdexkit.so from " + so.getAbsolutePath());
            return true;
        } catch (Throwable t) {
            XposedBridge.log(TAG + "native extract/load failed: " + t);
            return false;
        }
    }
}
