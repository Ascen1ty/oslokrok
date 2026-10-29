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
 * Each machanism is resolved dynamically via DexKit (structural
 * anchors in package tree) with a hardcoded fallbacks:
 *
 *   1. signal()  - original RASP detection-signal emit point (RaspDetectionDataSourceImpl.signal).
 *                  Reduntant on 10.19.0+ (as is removed), but is kept here for older builds.
 *
 *   2. AppVerifier.run() - the 10.19.0 startup verifier (oslo.core.startup). DexGuard VM launched 
 *                   by AppVerifierInitializer crashes (NPE / heap exhaustion) on tamper mismatch.
 *                  Nothing consumes its result, so replacing run() with no-op resolves the crash.
 */

public class Hook implements IXposedHookLoadPackage, IXposedHookZygoteInit {

    private static final String TARGET = "com.paypal.android.p2pmobile";
    private static final String IFACE  = "com.paypal.oslo.core.security.rasp.SignalRaspDetectionDataSource";
    private static final String IMPL   = "com.paypal.oslo.core.security.rasp.RaspDetectionDataSourceImpl";
    private static final String PKG    = "com.paypal.oslo.core.security.rasp";
    private static final String SIGNAL = "signal";

    private static final String STARTUP_PKG = "com.paypal.oslo.core.startup";
    private static final String APPVERIFIER = "com.paypal.oslo.core.startup.AppVerifier";
    private static final String RUN         = "run";

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

        Set<Member> signalTargets = new HashSet<>();
        Set<Member> verifierTargets = new HashSet<>();

        if (nativeOk) {
            DexKitBridge bridge = null;
            try {
                bridge = DexKitBridge.create(cl, true);

                try {
                    MethodDataList ms = bridge.findMethod(FindMethod.create().matcher(
                            MethodMatcher.create()
                                    .declaredClass(PKG, StringMatchType.Contains)
                                    .name(SIGNAL)
                                    .paramCount(0)));
                    for (MethodData md : ms) {
                        try { signalTargets.add(md.getMethodInstance(cl)); } catch (Throwable ignored) {}
                    }
                } catch (Throwable t) { XposedBridge.log(TAG + "query A failed: " + t); }

                try {
                    ClassDataList impls = bridge.findClass(FindClass.create().matcher(
                            ClassMatcher.create().addInterface(IFACE)));
                    for (ClassData cd : impls) {
                        try { signalTargets.add(cd.getInstance(cl).getDeclaredMethod(SIGNAL)); }
                        catch (Throwable ignored) {}
                    }
                } catch (Throwable t) { XposedBridge.log(TAG + "query B failed: " + t); }

                try {
                    MethodDataList ms = bridge.findMethod(FindMethod.create().matcher(
                            MethodMatcher.create()
                                    .declaredClass(STARTUP_PKG, StringMatchType.Contains)
                                    .name(RUN)
                                    .paramCount(0)));
                    for (MethodData md : ms) {
                        try { verifierTargets.add(md.getMethodInstance(cl)); } catch (Throwable ignored) {}
                    }
                } catch (Throwable t) { XposedBridge.log(TAG + "query C failed: " + t); }

            } catch (Throwable t) {
                XposedBridge.log(TAG + "DexKit init failed: " + t);
            } finally {
                if (bridge != null) try { bridge.close(); } catch (Throwable ignored) {}
            }
        }

        // signal()
        int signalHooks = 0;
        for (Member m : signalTargets) {
            if ((m.getModifiers() & Modifier.ABSTRACT) != 0) continue;
            try {
                XposedBridge.hookMethod(m, XC_MethodReplacement.returnConstant(null));
                signalHooks++;
                XposedBridge.log(TAG + "hooked (dynamic) " + m);
            } catch (Throwable t) { XposedBridge.log(TAG + "hook failed on " + m + ": " + t); }
        }
        if (signalHooks == 0) {
            try {
                XposedHelpers.findAndHookMethod(IMPL, cl, SIGNAL,
                        XC_MethodReplacement.returnConstant(null));
                signalHooks++;
                XposedBridge.log(TAG + "hooked (fallback) " + IMPL + "." + SIGNAL + "()");
            } catch (Throwable t) {
                XposedBridge.log(TAG + "signal fallback failed: " + t);
            }
        }

        // appverif
        int verifierHooks = 0;
        for (Member m : verifierTargets) {
            if ((m.getModifiers() & Modifier.ABSTRACT) != 0) continue;
            try {
                XposedBridge.hookMethod(m, XC_MethodReplacement.returnConstant(null));
                verifierHooks++;
                XposedBridge.log(TAG + "neutralised (dynamic) " + m);
            } catch (Throwable t) { XposedBridge.log(TAG + "verifier hook failed on " + m + ": " + t); }
        }
        if (verifierHooks == 0) {
            try {
                XposedHelpers.findAndHookMethod(APPVERIFIER, cl, RUN,
                        XC_MethodReplacement.returnConstant(null));
                verifierHooks++;
                XposedBridge.log(TAG + "neutralised (fallback) " + APPVERIFIER + "." + RUN + "()");
            } catch (Throwable t) {
                // pre-10.19.0
                XposedBridge.log(TAG + "no AppVerifier on this version: " + t);
            }
        }

        XposedBridge.log(TAG + "active on " + TARGET
                + ", signal hooks=" + signalHooks
                + ", verifier hooks=" + verifierHooks
                + (nativeOk ? " (dexkit)" : " (no-dexkit)"));
    }

    /** Load libdexkit.so */
    private boolean loadDexKitNative(XC_LoadPackage.LoadPackageParam lpparam) {
        if (nativeLoaded) return true;
        try { System.loadLibrary("dexkit"); nativeLoaded = true; return true; }
        catch (Throwable ignored) {}

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
