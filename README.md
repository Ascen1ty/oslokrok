[![GitHub release](https://img.shields.io/github/v/release/Ascen1ty/oslokrok?style=for-the-badge)](../../releases)
[![Downloads](https://img.shields.io/github/downloads/Ascen1ty/oslokrok/total?style=for-the-badge)](../../releases)

# Oslokrok - PayPal root-detection bypass

**A Vector (formerly Xposed/LSPosed) module that prevents the PayPal app from crashing on rooted devices.**

This crash is caused by PayPal's own on-device anti-tamper (RASP), which
kills the app a few seconds after launch on rooted devices. Oslokrok neutralises
the mechanism that causes this crash, allowing the PayPal app to run normally.

---

## 🪝 Oslokrok?
PayPal's internal package name = `com.paypal.oslo`.<br/>
Oslo = Norway.<br/>
Hook = `Krok` in Norwegian.<br/>
PayPal Hook = `Oslokrok.`<br/>

---

## ✨ Features

- ✅ Prevents on-launch anti-tamper crash (`AppVerifier` for 10.19.0+, `s=root` for pre-10.19.0).
- ✅ Self-healing: targets are resolved at runtime with DexKit, not hardcoded names.
- ✅ Falls back to fixed hooks if DexKit is unavailable.

---

## 🛠️ How It Works

- **AppVerifier (10.19.0+)** - this is a startup integrity check that crashes the process on a mismatch. No-opping its `run()` method prevents the crash.
- **Legacy (pre-10.19.0)**   - RASP has several detection channels, but only the root channel is set up to cause the crash. No-opping this channel means the crash never happens.

### 🔍 Target(s)

| Check | Method | Package |
| --- | --- | --- |
| AppVerifier (10.19.0+) | `AppVerifier.run()` | `com.paypal.oslo.core.startup` |
| Legacy (pre-10.19.0) | `RaspDetectionDataSourceImpl.signal()` | `com.paypal.oslo.core.security.rasp` |

Oslokrok locates both methods with [DexKit](https://github.com/LuckyPray/DexKit)
using structural anchors (package names + method shape) with a fixed-name fallback 
so hooks should survive updates, unless these are removed.

---

## 🧪 Requirements

- ✅ Root + an Xposed framework: **Vector** or **LSPosed** with Zygisk.
- ✅ Working root hiding (DenyList / HMA / Shamiko, etc).
- ❗ **arm64-v8a** only.
- ❗ Oslokrok only prevents the crash; it does **not** hide root from PayPal's servers.

---

## 🚀 Installation

1. Download the latest `Oslokrok-*.apk` from [Releases](../../releases) and install it.
2. Enable **Oslokrok** in your LSPosed / Vector app; confirm **PayPal** is in scope (ticked/selected).
3. Force-stop PayPal (and/or reboot) and reopen PayPal.

> ⚠️ Upon install, Play Protect will probably say it *"hasn't seen an app from  
> this developer"* - this is due to a new-signing-key reputation notice. Tap
> **More details → Install anyway**.

Check LSPosed/Vector log (filter `oslokrok`) for:
`signal hooks=1, verifier hooks=1 (dexkit)`.

---

## 🧠 Notes

- If an update changes the package/interface/method so that nothing hooks
  (`signal hooks=0, verifier hooks=0`), the anchors in
  `app/src/main/java/net/oslokrok/hook/Hook.java` need updating.
- Tested on v10.14.0, v10.16.0, v10.17.0, v10.18.0 and v10.19.0.

---

## 🙏 Credits

- **[Santand3rp](https://github.com/mwilky/Santand3rp)** by **mwilky** — for inspiring the
  initial concept for this project and the two-hook approach to defeating the in-process anti-tamper.
- **[DexKit](https://github.com/LuckyPray/DexKit)** by **LuckyPray** — the
  runtime dex-search engine that makes the hooks "self-healing".

---

## 📄 License

Oslokrok is released under the **MIT License** — see [`LICENSE`](LICENSE).

Release builds bundle third-party components (DexKit, Kotlin stdlib, FlatBuffers)
under their own licenses — see [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
DexKit is dual-licensed LGPL-3.0 / Apache-2.0 and is used here under Apache-2.0.

---

> This module is in no way affiliated with, or endorsed by, PayPal. No
> PayPal code, assets, or trademarks are included; "PayPal" is used
> only to name the app this module works with.
