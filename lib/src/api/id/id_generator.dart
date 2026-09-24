// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

import 'dart:math';
import 'dart:typed_data';

/// Generates trace and span IDs according to the W3C Trace Context specification.
class IdGenerator {
  static final _Prng _random = _Prng.seededFromOs();

  /// Generate a 16-byte trace ID.
  /// Returns bytes which can be formatted as a 32-char hex string.
  static Uint8List generateTraceId() {
    final bytes = Uint8List(16);

    // Generate random bytes until we get a non-zero ID
    do {
      _random.fillBytes(bytes);
    } while (_isZero(bytes));

    return bytes;
  }

  /// Generate an 8-byte span ID.
  /// Returns bytes which can be formatted as a 16-char hex string.
  static Uint8List generateSpanId() {
    final bytes = Uint8List(8);

    // Generate random bytes until we get a non-zero ID
    do {
      _random.fillBytes(bytes);
    } while (_isZero(bytes));

    return bytes;
  }

  /// Convert bytes to lowercase hex string.
  static String bytesToHex(List<int> bytes) {
    return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  }

  /// Check if all bytes are zero.
  static bool _isZero(List<int> bytes) {
    for (var byte in bytes) {
      if (byte != 0) return false;
    }
    return true;
  }

  /// Parse hex string to bytes.
  static Uint8List? hexToBytes(String hex) {
    if (hex.length % 2 != 0) return null;

    final bytes = Uint8List(hex.length ~/ 2);

    for (var i = 0; i < bytes.length; i++) {
      final hexByte = hex.substring(i * 2, (i * 2) + 2);
      final byte = int.tryParse(hexByte, radix: 16);
      if (byte == null) return null;
      bytes[i] = byte;
    }

    return bytes;
  }
}

/// A fast pseudo-random byte source used by [IdGenerator].
///
/// The previous implementation drew every ID byte from [Random.secure]. Each
/// `nextInt()` on a secure [Random] performs an operating-system entropy
/// call, so one span ID cost 8 OS calls and one trace ID 16 — measured at
/// roughly 40 µs per call on macOS, i.e. ~1 ms to start a single root span,
/// which made ID generation the dominant cost of creating a span under load.
///
/// The W3C Trace Context spec requires trace/span IDs to be random and
/// globally unique (§3.3.1), not cryptographically secure per byte — the same
/// trade-off other OpenTelemetry SDKs make (e.g. Java's `ThreadLocalRandom`,
/// Rust's per-thread ChaCha RNG). We therefore read entropy from the OS once
/// to seed this generator, then expand it locally.
///
/// The generator is Marsaglia's xorshift128 with a 128-bit state held as
/// four unsigned 32-bit words. All arithmetic is masked to 32 bits, so the
/// output sequence is identical on the VM and when compiled to JavaScript
/// (where `int` is a 64-bit float and unmasked 64-bit `+`/`*` would lose
/// precision); only XOR and shifts are used, never addition.
class _Prng {
  _Prng._(this._x, this._y, this._z, this._w);

  factory _Prng.seededFromOs() {
    final secure = Random.secure();
    var x = secure.nextInt(_mask32 + 1);
    var y = secure.nextInt(_mask32 + 1);
    var z = secure.nextInt(_mask32 + 1);
    var w = secure.nextInt(_mask32 + 1);
    // An all-zero state makes xorshift emit zeros forever. The probability
    // is 1 in 2^128, but the guard costs one comparison at startup.
    if ((x | y | z | w) == 0) {
      // coverage:ignore-line
      x = 0x9E3779B9; // Any fixed non-zero word works (golden ratio here).
    }
    return _Prng._(x, y, z, w);
  }

  static const int _mask32 = 0xFFFFFFFF;

  int _x;
  int _y;
  int _z;
  int _w;

  /// Advances the state and returns the new 32-bit word.
  int _nextWord() {
    final t = _x ^ ((_x << 11) & _mask32);
    _x = _y;
    _y = _z;
    _z = _w;
    _w = (_w ^ (_w >>> 19) ^ t ^ (t >>> 8)) & _mask32;
    return _w;
  }

  /// Fills [bytes] entirely with pseudo-random bytes.
  void fillBytes(Uint8List bytes) {
    var word = 0;
    var available = 0;
    for (var i = 0; i < bytes.length; i++) {
      if (available == 0) {
        word = _nextWord();
        available = 4;
      }
      bytes[i] = word & 0xFF;
      word >>>= 8;
      available--;
    }
  }
}
