# AIDL Fuzzer

[![Android CI](https://github.com/h4ckologic/AndroidAIDLFuzzer/workflows/Android%20CI/badge.svg)](https://github.com/h4ckologic/AndroidAIDLFuzzer/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Android](https://img.shields.io/badge/Android-7.0%2B-green.svg)](https://developer.android.com)
[![Kotlin](https://img.shields.io/badge/Kotlin-1.9.10-blue.svg)](https://kotlinlang.org)

AIDL Fuzzer is a generic Android AIDL service fuzzer that discovers vulnerabilities organically—no hardcoded exploit knowledge required.

## Table of Contents

1. [Overview](#overview)
2. [Features](#features)
3. [Quick Start](#quick-start)
4. [Installation](#installation)
5. [Usage](#usage)
6. [Understanding Results](#understanding-results)
7. [How It Works](#how-it-works)
8. [Architecture](#architecture)
9. [Building from Source](#building-from-source)
10. [Development Setup](#development-setup)
11. [Troubleshooting](#troubleshooting)
12. [Technical Details](#technical-details)
13. [Limitations](#limitations)
14. [Security & Responsible Use](#security--responsible-use)
15. [Contributing](#contributing)
16. [License](#license)

## Overview

The fuzzer works by:
- Enumerating exported AIDL services on-device
- Systematically exercising transaction codes 1–128
- Injecting inputs across multiple data types and boundary values
- Detecting crashes, exceptions, and service disconnects in real time

## Features

### Organic Vulnerability Discovery
- Works across arbitrary exported AIDL services
- No service-specific signatures or assumptions needed

### Comprehensive Input Testing
- Empty payloads and primitive boundary values
- Format strings (`%s`, `%n`, `%x`)
- Variable-length strings (16 up to 4096 bytes)
- Byte arrays and multi-parameter combinations

### Real-time Reporting
- Color-coded severity
- Traceable transaction code and input context
- Immediate visibility into crash types

## Quick Start

### Prerequisites
- Android device or emulator running Android 7.0+ (API 24+)
- USB debugging enabled / emulator with ADB
- ADB installed on your workstation

### Steps
```bash
# Clone
git clone https://github.com/h4ckologic/AndroidAIDLFuzzer.git
cd AndroidAIDLFuzzer

# Build
./gradlew clean assembleDebug

# Install on device/emulator
adb install app/build/outputs/apk/debug/app-debug.apk
```

### First Run
1. Launch **AIDL Fuzzer** on the device
2. Allow the service discovery to complete (a few seconds)
3. Pick a target service from the list
4. Tap **Fuzz Until Crash** to begin
5. Monitor results in real time

## Installation

### Prerequisites
- Android rooted device or emulator running Android 7.0+ (API 24+)
- ADB access
- Optional: a known vulnerable test target

### Install
```bash
git clone https://github.com/h4ckologic/AndroidAIDLFuzzer.git
cd AndroidAIDLFuzzer
./gradlew clean assembleDebug
adb install app/build/outputs/apk/debug/app-debug.apk
```

## Usage

1. Launch the app
2. Select a discovered exported service
3. Tap **Fuzz Until Crash**
4. Observe live results and stop any time

## Understanding Results

### Severity Levels
- 🔴 **CRASH** – process killed/disconnected
- 🟠 **EXCEPTION** – RemoteException or other thrown exception
- �� **TIMEOUT** – binder call hung or exceeded threshold
- 🟢 **ANOMALY** – suspicious behavior worth investigation

### Priorities
- High: small-input crashes, format strings, integer overflows
- Medium: large buffer exceptions, timeouts
- Low: permission denials or input validation errors

## How It Works

1. **Discovery** – scans installed packages for exported, bindable services.
2. **Binding** – connects to a user-selected target via `bindService`.
3. **Fuzzing Loop** – iterates transaction codes 1–128 with structured inputs.
4. **Detection** – captures binder failures, thrown exceptions, and crashes.

## Architecture
```
app/src/main/java/com/aidlfuzzer/
├── fuzzer/
│   ├── FuzzEngine.kt         # Core engine
│   ├── FuzzResult.kt         # Result model
│   └── TransactionFuzzer.kt  # Input generation
├── utils/
│   ├── ServiceDiscovery.kt   # Enumerates services
│   └── CrashDetector.kt      # Classifies crashes
└── MainActivity.kt           # Jetpack Compose UI
```

## Building from Source

### Requirements
- Android Studio Arctic Fox or newer
- JDK 17
- Android SDK (API 24+)

### Commands
```bash
export JAVA_HOME=/path/to/jdk17
./gradlew clean assembleDebug
```
APK output: `app/build/outputs/apk/debug/app-debug.apk`

## Development Setup

### Project Structure
```
AIDLFuzzer/
├── app/
│   └── src/main/
│       ├── java/com/aidlfuzzer/...
│       ├── res/
│       └── AndroidManifest.xml
├── build.gradle.kts
├── settings.gradle.kts
├── gradle/
└── README.md
```

### Key Files
- `FuzzEngine.kt` – binder fuzz logic
- `ServiceDiscovery.kt` – enumerates exported services
- `MainActivity.kt` – Compose UI surface
- `FuzzResult.kt` – data model for findings

### Run Tests
```bash
./gradlew test
./gradlew connectedAndroidTest  # requires device/emulator
```

### Workflow
1. `git checkout -b feature/my-change`
2. Implement feature/fix
3. `./gradlew test assembleDebug`
4. `git commit -m "Add X"`
5. `git push origin feature/my-change`
6. Open PR on GitHub

## Troubleshooting

| Issue                          | Fix |
|--------------------------------|-----|
| Gradle sync fails              | `./gradlew clean`; delete `.gradle`; re-run build |
| SDK location missing           | Create `local.properties` with `sdk.dir=/path/to/sdk` |
| Device not listed by ADB       | `adb kill-server && adb start-server`; check USB debugging |
| “Unsupported class file” error | Ensure JDK 17 is in use (`java -version`) |
| INSTALL_FAILED_UPDATE…         | `adb uninstall com.aidlfuzzer` before re-install |

## Technical Details

- Transaction codes: 1–128
- Integer test set: min/max, -1, 0xFFFFFFFF, etc.
- String sizes: 16 up to 4096 bytes
- Combined tests: multi-parameter parcels
- Throughput: ~50–100 transactions/second

## Limitations

1. Only exported/bindable services can be fuzzed
2. Cannot bypass service-level auth or gating
3. Business-logic bugs outside binder path may be missed
4. Race conditions and timing-sensitive bugs are out-of-scope

## Security & Responsible Use

- Use **only** on systems/apps you own or have written permission to test
- Respect legal boundaries (CFAA, GDPR, etc.)
- Follow responsible disclosure: notify vendors, allow fix window, coordinate release
- Back up devices before fuzzing and monitor stability

If you discover a vulnerability in this project itself, avoid public issues; email maintainers and allow reasonable remediation time.

## Contributing

1. Fork and branch from `main`
2. Adhere to Kotlin style guide and project conventions
3. Include tests or manual verification notes
4. Use clear commit messages (imperative, ≤72 chars)
5. Update docs if behavior changes
6. Open PRs with context and testing evidence

### Example Commit
```
Add custom transaction range controls

- allow users to configure min/max ranges
- validate ranges in UI
- update documentation with new option

Fixes #42
```

## License

MIT License © 2025 AIDLFuzzer Contributors

```
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

### Educational Use Notice
- Built for research, demos, and authorized penetration testing
- Authors disclaim liability for misuse
- Do not run against systems without explicit consent

## Authors

- @hardw00t 
- @h4ckologic 

This tool was crafted as part of the HackLu 2025 conference demo to showcase organic Android AIDL service fuzzing techniques.

## References
- [Android Binder IPC](https://developer.android.com/guide/components/aidl)
- [AIDL Specification](https://source.android.com/docs/core/architecture/aidl)
- [Android Security Best Practices](https://developer.android.com/topic/security/best-practices)
- [Kotlin Coding Conventions](https://kotlinlang.org/docs/coding-conventions.html)

---

**Happy Fuzzing! 🐛🔍**
Use this tool responsibly and ethically.
