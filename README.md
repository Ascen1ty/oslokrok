[![GitHub release](https://img.shields.io/github/v/release/Ascen1ty/oslokrok?style=for-the-badge)](../../releases)
[![Downloads](https://img.shields.io/github/downloads/Ascen1ty/oslokrok/total?style=for-the-badge)](../../releases)

# Oslokrok - PayPal root-detection bypass

**A Vector (formerly Xposed/LSPosed) module that prevents the PayPal app from crashing on rooted devices.**

This crash is caused by PayPal's own on-device anti-tamper (RASP), which throws
`RootDetectionSecurityException` (`s=root`) a few seconds after launch. Oslokrok
neutralises it at the single point where the detection signal is emitted.

---

## 🪝 Oslokrok?
PayPal's internal package name = `com.paypal.oslo`.<br/>
Oslo = Norway.<br/>
Hook = `Krok` in Norwegian.<br/>
PayPal Hook = `Oslokrok.`<br/>

---

## ✨ Features

- ✅ Prevents on-launch `s=root` crash.
- ✅ Self-healing: the target method is resolved at runtime with DexKit, not hardcoded names.
- ✅ Falls back to a fixed hook if DexKit is unavailable.

---

## 🛠️ How It Works

PayPal's RASP wires several detection channels, but **only the `"root"` channel
is set to crash the app**. They all funnel through one emit method. No-opping it means
the crash is never scheduled.

### 🔍 Target

| What | Value |
| --- | --- |
| Method | `RaspDetectionDataSourceImpl.signal()` |
| Package | `com.paypal.oslo.core.security.rasp` |
| Interface | `SignalRaspDetectionDataSource` |

Oslokrok locates this method with [DexKit](https://github.com/LuckyPray/DexKit)
using structural anchors (interface + a 0-arg `signal()` in the `rasp` package)
so it should survive obfuscation/name changes, across future updates.

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
`hooked (dynamic) …signal()` and `signal hooks=1 (dexkit)`.

---

## 🧠 Notes

- If an update changes the package/interface/method so that nothing
  hooks (`signal hooks=0`), the anchors in `app/src/main/java/net/oslokrok/hook/Hook.java` 
  need updating.
- "Self-Healing" function hasn't been tested as this module has currently only been tested on
  the latest app version (v10.14.0).

---

## 🙏 Credits

- **[Santand3rp](https://github.com/mwilky/Santand3rp)** by **mwilky** — for inspiring the
  initial concept for this project and the two-hook approach to defeating the in-process anti-tamper.
- **[DexKit](https://github.com/LuckyPray/DexKit)** by **LuckyPray** — the
  runtime dex-search engine that makes the hook "self-healing".

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
