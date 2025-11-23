# AIDL Fuzzer

[![Android CI](https://github.com/h4ckologic/AndroidAIDLFuzzer/workflows/Android%20CI/badge.svg)](https://github.com/h4ckologic/AndroidAIDLFuzzer/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Android](https://img.shields.io/badge/Android-7.0%2B-green.svg)](https://developer.android.com)
[![Kotlin](https://img.shields.io/badge/Kotlin-1.9.10-blue.svg)](https://kotlinlang.org)

A generic Android AIDL service fuzzer that organically discovers vulnerabilities without hardcoded exploit knowledge.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [t)
- [Installation](#installaion)
- [Usage](#usagets)
- [How It Works](#how-it-works)
- [Architecture](#architecure)
- [Building from Source](#building-from-ourceTeechnical Details](#technical-details)
- [Limitations](#limitations)
- [Scurity oiese](#curity-oie)
- [Contributing](contributing)
- [License](license)

# Overview

This fuzzer automatically discovers and exploits vulnerabilities in Android AIDL services by:
- Discovering all exported services on the device
- Systematically testing transaction codes 1-128
- Testing with various input types and attack patterns
- Detecting crashes, exceptions, and service disconnections
- Reporting discovered vulnerabilities in real-time

## Features

### Organic Vulnerability Discovery
- No hardcoded knowledge of target vulnerabilities
- Genericfuzzing patterns that work across all AIDL services
- Systematic exploration of the entire transaction code space

 Comprehensive Input Testing
- Empty inputs
- Integer boundary values (0, MAX, MIN, -1, 0xFFFFFFFF)
- Format string patterns (%s, %n, %x)
- Buffer overflow strings (16, 32, 64, 256, 1024, 2048 bytes)
- Byte arrays of various sizes
- Combinations(int+int, int+string, string+bytes)

## Real-time Results
- Live vulnerability discovery during fuzzing
- Color-coded results by severity
- Detailed crash information including transaction code and input

Installation

### Prerequisites
- Android device with API level 24+ (Android 7.0+)
- ADB installed on your computer
- Target vulnerable app installed  esn

###Install the Fuzzer

```bash
# Clone the repository
git clone https://github.com/h4ckologic/AndroidAIDLFuzzer.git
cd AIDLFuzzer

# Build the project
./gradlew clean assembleDebug

# Install the APK
adb install app/build/outputs/apk/debug/app-debug.apk
```

## Usage

### 1. Launch the Fuzzer

Open the AIDL Fuzzer app on your Android device.

### 2. Select Target Service

The fuzzer will automatically discover all exported services on your device.

1. Wait for service discovery to complete 
2. Scroll through the list of discovered services
.Tap on a service to select it

### 3. Start Fuzzing

1. Click the "Fuzz n" button
2. Watc the rore inat
3. est will appea in rte sults is

### 4. Review Results

Each result shows:
- Transactionc code that caused the rash
- Input ype at daatriggered i
- Type CRASH, EXCEPTION, TIMEOUT, ANOMALY
- escription

Coo ondig
 Re CRASH: Service crashed or disconnected
-  EXCEPTION: RemoteException or other exception thrown
-  TIMEOUT: Service hung or timed out
-  ANOMALY: Unusual behavior detected

### t o Fig
Clik e opton toat ing at n ite
 she wit ecureos

o ts the fuer wit te iteional vnale erosuln 

### s eceun

  h  ulnerable pp st it intall vulnerableapp
2. n Sste eures e a ee  evice eerure ter a memor.Document ur indisote ransacion   and rerouibiltest stmatia  est oe service mesrtgi less critical services

## How It Works

### Service Discovery
1. Scans all installed packages using PackageManager
2. Fiters forservies with `android:exported="true"`
3. Presents them n the UI for seletion

### Fuzzing Engine
1. Binds to the seected service using `bindService()`
2. For eachtranction code (1-128):
   - Tests with emty inut
   - Tests with integers (boundary values, overflow candidates)
   - Tests with longs (boundary values)
   - Tests with floats (NaN, infinity, special values)
   - Tests with strings (format strings, buffer overflows, special chars)
   - Tests with byte arrays (various sizes)
   - Tests with combinations (multiple parameters)

3. For each test:
   - Creates a Parcel with test data
   - Calls `binder.transact(code, data, reply, 0)`
   - Catches exceptions and disconnections
   - Records failures as discovered vulnerabilities

### Crash Detection
The fuzzer detects:
- `RemoteException`: Service crashed or disconnected
- Service returning `false` from `transact()`: Service rejected the call
- Any uncaught exception: Unexpected crash
- Service disconnection: Complete service failure

All crashes are logged with:
- Exact transaction code
- Input description
- Crash type and message

## Architecture

```
AIDLFuzzer/
├── appfuzzer/
│   ├──  FuzzEngine.kt     # Core fuzzing logic
│├── FuzzResult.kt         # Result data model
│  └── TransactionFuzzer.kt  # Input generation helpers
├── utils/
│  ├── ServiceDiscovery.kt   # Service enumeration
│  └── CrashDetector.kt      # Crash classification
└── MainActivity.kt          # Compose UI
```

## ioered ulerabilitie
he ui Seureocsln yo shh4ckologiculd scoe

DomentProeSrce
 ranacion  it i UsAftere ras
 ratio it string: Sck er ero
- anation  ith tsrin t uer overflow

euretoraeerce
 Transat on it whlarge bfer: ep buffer overlo
- ransacon  wth yte ap fr oer

**ocuntasSi:**
- rasct in- ith ii teer oerflo
- rasacin - it  n Forat sting lnerabilies

ll discoered oranical witot hardcdgin

## Buildi rom urce


```bash# e Java is ace
export JAVA_HOME=/Library/Java/JavaVirtualMachines/openjdk-17.jdk/Contents/Home

# ild
rle lnassleebu

#  laintall app/build/outpus/apk/debug/app-debug.apk
```

## Technic Detais

 FuzzingParameters
- Transaction codes: 1-128 (covers all standard AIDL methods)
- **Integer test values**: 8 boundary cases per code
- String test patterns: 20+ different patterns
- Byte array sizes: 9 different sizes (0 to 4096 bytes)
- Combinations: 4 different multi-parameter tests

Total tests per service: ~5000+ individual test cases

Performance
- Fuzzing speed: ~50-100 transactions per second
- Full service fuzz: 30-60 seconds
- Memory efficient: Parcels are recycled after each test

## Limitations

1. Only workswith exported services
2. Cannot bypass authentication/authorization checks
3. Does not test service-specific business logic
4. May not discover all vulnerability types (e.g., race conditions)
5. Requires the target service to be bindable

## Security  otis

**This tool is deigned for:
- Security research
- Penetration testing with authorization
- Educational purposes
- Conference demonstrations

Do T use on:**
- Services you do not own or have permission to test
- Production systems without explicit authorization
- hird-party apps without consent

## iense

 ciense  ee C ile or detais

ucational use on ee  n CS file

## ensos

 D: d sreensots here 
 ample
ice electiondocscenotssericeseletionpn
uin in roresocscreesotuingrorespng
iscoered uleaiitiesdocsscreenshotsresulspn
--

creensot coing sn. The a fetres
 Srice discover and selection interfae
- ea-time fuing progress iniator Color-cde uleralit resuls display

## ontributing

Contributions are welcome lease read ONTRIBUTING.CONTRIBUTING.d for details n our oe of out and te ress for suitting pull euests.

## Authors

Created for security conference demonstration of AIDL fuzzing techniques.

## References

- [Android Binder IPC documentation](https://developer.android.com/guide/components/aidl)
- [AIDL specification](https://source.android.com/docs/core/architecture/aidl)
- [Android security best practices](https://developer.android.com/topic/security/best-practices)
