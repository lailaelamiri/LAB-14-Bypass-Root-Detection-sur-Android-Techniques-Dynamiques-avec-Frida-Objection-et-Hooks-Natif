# Android Root Detection Bypass — Frida, Objection, Medusa, and Magisk

**Target:** `owasp.mstg.uncrackable1`
**Device:** Android Emulator 5554
**CPU Architecture:** x86
**Frida Version:** 17.9.1
**Objection Version:** 1.12.4
**Date:** 2026-05-17

---

## Overview

This lab demonstrates four approaches to bypassing root detection on the OWASP MAS Uncrackable Level 1 Android application. The approaches operate at different layers of the stack: raw Frida scripts hook Java APIs directly at the runtime level; Objection wraps those same hooks behind a single CLI command; Medusa provides a module-based instrumentation framework as an alternative to Objection; and Magisk operates at the system level, masking root from the OS upward rather than intercepting individual API calls.

The app detects emulator and root environments at launch and immediately terminates — the goal is to neutralize every detection vector so the main interface loads normally.

---

## Environment

| Component | Details |
|---|---|
| Host OS | Windows 11 |
| Emulator | Android Emulator x86 — API 30 |
| CPU Architecture | x86 |
| Frida Version | 17.9.1 |
| Objection Version | 1.12.4 |
| Python | 3.x |
| ADB | Platform Tools (latest) |

---

## Prerequisites

```
python --version
pip --version
adb devices
frida --version
objection --version
```

Confirm `adb devices` shows `emulator-5554   device` and that Frida and Objection versions are installed before proceeding.

---

## Part 1 — Environment Setup

### 1.1 Push and Start frida-server

Identify the emulator architecture:

```
adb shell getprop ro.product.cpu.abi
```

Download the matching `frida-server` binary from the Frida releases page, matching the exact Frida client version. Push it to the device and launch it with root privileges:

```
adb root
adb push frida-server /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server
adb shell "/data/local/tmp/frida-server &"
```

### 1.2 Verify Device Visibility

```
frida-ps -Uai
```

The target app should appear in the list:

```
-  Uncrackable1  owasp.mstg.uncrackable1
```

### 1.3 Install the Target APK

```
adb install UnCrackable-Level1.apk
```

---

## Part 2 — Observing the Root Detection

Launch the app without any bypass:

```
adb shell am start -n owasp.mstg.uncrackable1/sg.vantagepoint.uncrackable1.MainActivity
```

The app displays a blocking dialog immediately on startup:

```
Root detected!
This is unacceptable. The app is now going to exit.
[ OK ]
```

Pressing OK terminates the process. The app is completely unusable in this state.

**Screenshot — Root detected dialog before bypass**

---

## Part 3 — Bypass with Raw Frida

### 3.1 What the App Checks

UnCrackable1 performs three categories of Java-side root checks:

- `android.os.Build.TAGS` — looks for the string `test-keys`, which is present on emulators and rooted builds
- `java.io.File.exists()` — probes the filesystem for `su` and `busybox` binaries
- `java.lang.Runtime.exec()` — attempts to execute `su` and `which su` to confirm shell access

### 3.2 The Bypass Script

Create `bypass_root.js`:

```javascript
Java.perform(function () {

  // 1) Build.TAGS -> release-keys
  try {
    const Build = Java.use("android.os.Build");
    Object.defineProperty(Build, "TAGS", { get: function() { return "release-keys"; } });
    console.log("[+] Build.TAGS hooked");
  } catch (e) { console.log("[-] Build.TAGS failed:", e); }

  // 2) File.exists() -> block su/busybox paths
  try {
    const File = Java.use("java.io.File");
    const suspicious = [
      "/system/bin/su", "/system/xbin/su", "/sbin/su",
      "/system/app/Superuser.apk", "/system/bin/busybox"
    ];
    File.exists.implementation = function () {
      const p = this.getAbsolutePath();
      if (suspicious.indexOf(p) !== -1) {
        console.log("[+] File.exists blocked:", p);
        return false;
      }
      return this.exists.call(this);
    };
    console.log("[+] File.exists hooked");
  } catch (e) { console.log("[-] File.exists failed:", e); }

  // 3) Runtime.exec -> block su commands
  try {
    const Runtime = Java.use("java.lang.Runtime");
    Runtime.exec.overload("java.lang.String").implementation = function (cmd) {
      if (cmd.includes("su") || cmd.includes("busybox")) {
        console.log("[+] Runtime.exec blocked:", cmd);
        return this.exec("echo");
      }
      return this.exec(cmd);
    };
    console.log("[+] Runtime.exec hooked");
  } catch (e) { console.log("[-] Runtime.exec failed:", e); }

  console.log("[+] All hooks installed");
});
```

### 3.3 Injection

```
frida -U -f owasp.mstg.uncrackable1 -l bypass_root.js
```

When the Frida REPL appears, type `%resume` to resume the main thread.

Note: `--no-pause` was removed in Frida 16+. Use `%resume` in the REPL instead.

### 3.4 Expected Console Output

```
[+] Build.TAGS hooked
[+] File.exists hooked
[+] Runtime.exec hooked
[+] All hooks installed
[+] File.exists blocked: /system/bin/su
[+] File.exists blocked: /system/xbin/su
[+] File.exists blocked: /system/app/Superuser.apk
```

**Screenshot — Frida console output after injection**

### 3.5 Result

The app loads its main interface without the root detection dialog. The secret string input field is accessible and the VERIFY button is responsive.

**Screenshot — App running normally after Frida bypass**

---

## Part 4 — Hook Reference

| Target | Hook Mechanism | Effect |
|---|---|---|
| `android.os.Build.TAGS` | `Object.defineProperty` on static field | Returns `release-keys` instead of `test-keys` |
| `java.io.File.exists()` | Method implementation override | Returns `false` for all paths in the blocklist |
| `java.lang.Runtime.exec()` | Overload-specific override | Replaces `su`/`busybox` commands with `echo` |

---

## Part 5 — Bypass with Objection

### 5.1 Installing Objection

```
pip install --upgrade objection
```

Verify the installation:

```
objection --help
```

### 5.2 Attaching to the Target

```
objection -g owasp.mstg.uncrackable1 explore
```

The Objection prompt confirms a live session:

```
(object)inject(ion) v1.12.4
Runtime Mobile Exploration

owasp.mstg.uncrackable1 (run) on (Android: 11) [usb] #
```

**Screenshot — Objection console connected to target**

### 5.3 Disabling Root Detection

Inside the Objection prompt:

```
android root disable
```

Objection registers a background job:

```
(agent) Registering job 975458. Name: root-detection-disable
```

Verify the active job:

```
jobs list
```

```
Job ID   Type   Name
------   ----   --------------------
975458   hook   root-detection-disable
```

**Screenshot — Objection jobs list showing active hook**

### 5.4 What android root disable Does

Behind the command, Objection injects a Frida script covering the following Java-side checks:

| Hook Target | Action |
|---|---|
| `android.os.Build.TAGS` | Forces return value to `release-keys` |
| `java.io.File.exists()` | Returns `false` for paths containing `su` and `busybox` |
| `Runtime.getRuntime().exec()` | Blocks execution of `su` and `which su` |
| Root management package checks | Returns empty or negative results |

### 5.5 Result

With the job active, the app renders its main interface without any detection dialog.

**Screenshot — App running cleanly after Objection bypass**

---

## Part 6 — Native Layer Observation

Some apps bypass Java entirely and use native C calls to probe the filesystem. These are not covered by `android root disable` and require a separate Frida native hook or `frida-trace` for inspection.

To observe native filesystem calls while the app is running:

```
frida-trace -U -p <PID> -i open -i access -i stat
```

`frida-trace` auto-generates handler stubs for each intercepted function and provides a live web UI at `localhost:46682`. Calls to `open()` and `stat()` targeting `/system/bin/su` and related paths confirm the presence of native-layer checks.

To block these at the native level, hook `libc.so` exports directly using `Interceptor.attach` and `Module.findExportByName`, returning `-1` for any suspicious path argument.

**Screenshot — frida-trace output showing native open() and stat() calls**

---

## Part 7 — Bypass with Medusa

Medusa is an extensible instrumentation framework built on Frida that organizes instrumentation into reusable modules. It is an alternative to Objection for analysts who prefer a module-driven workflow.

### 7.1 Installation

```
pip install medusa-framework
```

### 7.2 Attaching to the Target

Start a Medusa session against the target package:

```
medusa -f owasp.mstg.uncrackable1
```

### 7.3 Loading the Root Bypass Module

Inside the Medusa prompt, load the built-in root bypass module:

```
use root-bypass
run
```

Medusa injects hooks covering the same Java-side vectors as Objection: `Build.TAGS`, `File.exists()`, and `Runtime.exec()`. The module output confirms each hook as it is registered.

**Screenshot — Medusa console with root-bypass module active**

### 7.4 Result

With the module running, the app launches without the root detection dialog. The approach is equivalent to `android root disable` in Objection but organized around a named module system, making it easier to combine multiple bypass modules in a single session.

---

## Part 8 — System-Level Masking with Magisk

Frida, Objection, and Medusa all operate at the process level — they intercept specific API calls inside the running app. Magisk operates differently: it masks root at the system level before the app ever starts, so no in-process hooks are needed.

### 8.1 When to Use Magisk

Magisk is the right choice when:

- The app checks root via Google Play Integrity or SafetyNet rather than Java filesystem APIs
- The app inspects system properties that Frida hooks cannot easily intercept
- A global, persistent bypass is needed across multiple apps without injecting scripts on each launch

### 8.2 Setup Overview

On a physical device rooted with Magisk:

1. Enable Zygisk in Magisk settings
2. Open the DenyList and add the target app, Play Services, and Play Store
3. Install relevant modules: Play Integrity Fix, MagiskHide Props Config, Shamiko
4. Clear Play Store and Play Services data, reboot, and verify

### 8.3 Limitations

Magisk successfully bypasses Basic and Device integrity checks. Strong Integrity (hardware-attested) is generally not bypassable without a hardware-level vulnerability. On emulators, Magisk is not applicable — it requires a physical device with a bootloader that supports custom boot images.

---

## Part 9 — Tool Comparison

| Aspect | Raw Frida | Objection | Medusa | Magisk |
|---|---|---|---|---|
| Bypass layer | Java / Native | Java | Java | System |
| Root bypass command | Custom JS script | `android root disable` | `use root-bypass` | DenyList config |
| Code required | ~25 lines JS | 0 | 0 | 0 |
| Native hook support | Manual `Interceptor.attach` | Requires raw Frida | Requires raw Frida | N/A |
| Works on emulator | Yes | Yes | Yes | No |
| Persistent across launches | No | No | No | Yes |
| Play Integrity bypass | No | No | No | Partial |

Raw Frida gives full control at the cost of writing instrumentation code. Objection and Medusa remove that burden for standard patterns. Magisk is the only option when the detection mechanism operates below the application layer.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `unrecognized arguments: --no-pause` | Option removed in Frida 16+ | Remove flag, use `%resume` in the REPL |
| `Failed to spawn: InvocationTargetException` | Insufficient permissions | Run `adb root` before starting frida-server |
| `unable to find process` | App already closed | Use `-f` to spawn, not `-n` to attach |
| Native hooks produce no logs | App started before injection | Always use `-f` to spawn fresh |
| `ClassNotFoundException: RootBeer` | Library not present in this APK | Expected, safe to ignore |

---

## Detection Vectors Neutralized

```
Uncrackable1 root checks
├── Java layer
│   ├── Build.TAGS == "test-keys"          --> patched (release-keys)
│   ├── File.exists(/system/bin/su)        --> patched (false)
│   ├── File.exists(/system/xbin/su)       --> patched (false)
│   ├── File.exists(/system/app/Superuser) --> patched (false)
│   └── Runtime.exec("su")                 --> patched (blocked)
└── Native layer (observed via frida-trace)
    ├── open("/system/bin/su")             --> observable
    └── stat("/system/bin/su")             --> observable
```

---

## References

- [OWASP Mobile Security Testing Guide (MASTG)](https://mas.owasp.org/MASTG/)
- [Frida Documentation](https://frida.re/docs/)
- [Objection by sensepost](https://github.com/sensepost/objection)
- [Medusa Framework](https://github.com/Ch0pin/medusa)
- [Magisk by topjohnwu](https://github.com/topjohnwu/Magisk)
- [UnCrackable Mobile Apps — OWASP](https://mas.owasp.org/crackmes/)

---

## Disclaimer

This lab was conducted in a controlled environment against intentionally vulnerable applications designed for security training. Do not apply these techniques to applications or devices without explicit authorization.
