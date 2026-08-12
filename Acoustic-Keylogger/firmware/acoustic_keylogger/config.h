#pragma once
#include <Arduino.h>

// Target: Arduino Uno / Nano (ATmega328P, 16 MHz).
//
// Hardware:
//   MAX9814 electret microphone amplifier → A0 (analog)
//     The MAX9814 auto-gain amplifier outputs a centred signal (bias ~1.25 V)
//     with selectable gain (40/50/60 dB via GAIN pin).
//   Optional trigger LED   → D13  (lights during capture window)
//
// Capture strategy:
//   The firmware continuously monitors A0 for an energy threshold crossing
//   (onset detection). When triggered, it captures PRE_SAMPLES samples before
//   the trigger (from a ring buffer) plus POST_SAMPLES after, then ships the
//   full window over serial as a binary burst.
//
// Timing:
//   Timer1 CTC fires at SAMPLE_RATE_HZ. At 8000 Hz each sample takes 125 µs.
//   analogRead() at default prescaler 128 takes ~104 µs — tight but viable.
//   To reduce ADC time: we set prescaler 64 → ~52 µs per conversion, leaving
//   73 µs margin within the 125 µs Timer1 period.

// ── Sampling ──────────────────────────────────────────────────────────────────
static constexpr uint16_t SAMPLE_RATE_HZ  = 8000;   // Hz
// Window: 10 ms pre-trigger + 40 ms post-trigger = 50 ms total per keystroke.
static constexpr uint16_t PRE_SAMPLES     = 80;     // 10 ms  @ 8 kHz
static constexpr uint16_t POST_SAMPLES    = 320;    // 40 ms  @ 8 kHz
static constexpr uint16_t WINDOW_SAMPLES  = PRE_SAMPLES + POST_SAMPLES;  // 400

// Pre-trigger ring buffer size must be >= PRE_SAMPLES and a power of 2.
static constexpr uint16_t PRE_BUF_SIZE    = 128;    // power of 2 >= 80

// ── Onset detection ───────────────────────────────────────────────────────────
// Onset fires when a short-term energy window exceeds ONSET_THRESHOLD times
// the background energy estimate. The background is updated continuously with
// a slow exponential moving average when no onset is active.
static constexpr uint16_t ONSET_WINDOW    = 16;     // samples for short-term energy
static constexpr float    ONSET_RATIO     = 6.0f;   // energy ratio to trigger
static constexpr float    BG_ALPHA        = 0.002f; // background EMA coefficient
// Minimum samples between successive triggers (refractory period).
static constexpr uint16_t REFRACTORY_SAMPLES = 400; // 50 ms

// ── ADC ───────────────────────────────────────────────────────────────────────
static constexpr uint8_t  MIC_PIN         = A0;
// Bias: MAX9814 outputs ~VCC/2. Subtract this to get a centred signal.
// With 5 V supply, bias ≈ 512 ADC counts (10-bit).
static constexpr int16_t  ADC_BIAS        = 512;

// ── Serial protocol ───────────────────────────────────────────────────────────
static constexpr uint32_t BAUD_RATE       = 500000;
// Packet: 4-byte header + WINDOW_SAMPLES × 2 bytes (int16_t samples)
//   'K'          — keystroke marker
//   uint16_t     — label byte sent by host before capture (0 = unlabelled)
//   uint16_t     — sample count (always WINDOW_SAMPLES)
//   int16_t[N]   — raw samples, little-endian, bias-subtracted
static constexpr uint8_t  PKT_KEYSTROKE   = 'K';
static constexpr uint8_t  PKT_LABEL       = 'L';   // host → fw: set label
static constexpr uint8_t  PKT_IDENT       = 'I';
static constexpr uint8_t  PKT_READY       = 'R';   // fw → host: ready

static constexpr uint8_t  STATUS_PIN      = 13;
