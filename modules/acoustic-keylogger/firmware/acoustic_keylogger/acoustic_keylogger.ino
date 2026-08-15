#include "config.h"

// ── Pre-trigger ring buffer ───────────────────────────────────────────────────
// Continuously filled by the Timer1 ISR with the most recent PRE_BUF_SIZE
// bias-subtracted samples. When an onset fires, the last PRE_SAMPLES entries
// are copied into the capture window before the post-trigger samples.
static int16_t g_pre_buf[PRE_BUF_SIZE];
static uint16_t g_pre_head = 0;   // write index (wraps with bitmask)

// ── Capture window ────────────────────────────────────────────────────────────
static int16_t  g_window[WINDOW_SAMPLES];
static uint16_t g_win_idx   = 0;
static bool     g_capturing = false;

// ── Onset detection state ─────────────────────────────────────────────────────
// Short-term energy is computed over ONSET_WINDOW samples.
// Background energy is a slow EMA updated when not capturing.
static uint32_t g_st_energy  = 0;    // sum of squares for current window
static float    g_bg_energy  = 500.0f; // background energy estimate
static uint16_t g_refractory = 0;    // samples remaining in refractory period
static int16_t  g_st_buf[ONSET_WINDOW] = {};
static uint8_t  g_st_idx = 0;

// ── Labels and state ──────────────────────────────────────────────────────────
static uint8_t  g_label     = 0;    // current label set by host
static bool     g_send_ready = false; // window ready to transmit

// ── Timer1 CTC configuration ──────────────────────────────────────────────────
// Prescaler 8 → tick = 0.5 µs. OCR1A = F_CPU/(8*rate) - 1 = 249 at 8 kHz.
static constexpr uint16_t T1_OCR = (16000000UL / (8UL * SAMPLE_RATE_HZ)) - 1;

// ── ADC prescaler 64 → ADC clock = 250 kHz → ~52 µs per conversion ───────────
static void setADCPrescaler64() {
    ADCSRA = (ADCSRA & ~0x07) | 0x06;  // ADPS2:1, ADPS0:0 → /64
}

// ── ISR ───────────────────────────────────────────────────────────────────────
ISR(TIMER1_COMPA_vect) {
    int16_t raw    = static_cast<int16_t>(analogRead(MIC_PIN));
    int16_t sample = raw - ADC_BIAS;

    // Always push into pre-trigger ring buffer.
    g_pre_buf[g_pre_head & (PRE_BUF_SIZE - 1)] = sample;
    g_pre_head++;

    if (g_capturing) {
        g_window[g_win_idx++] = sample;
        if (g_win_idx >= WINDOW_SAMPLES) {
            g_capturing   = false;
            g_send_ready  = true;
            g_refractory  = REFRACTORY_SAMPLES;
        }
        return;
    }

    // ── Update short-term energy window ───────────────────────────────────────
    int32_t sq_old = static_cast<int32_t>(g_st_buf[g_st_idx]) *
                     static_cast<int32_t>(g_st_buf[g_st_idx]);
    int32_t sq_new = static_cast<int32_t>(sample) * sample;
    g_st_energy    = static_cast<uint32_t>(
        static_cast<int32_t>(g_st_energy) - sq_old + sq_new
    );
    g_st_buf[g_st_idx] = sample;
    g_st_idx = (g_st_idx + 1) % ONSET_WINDOW;

    // ── Refractory period ─────────────────────────────────────────────────────
    if (g_refractory > 0) {
        g_refractory--;
        g_bg_energy += BG_ALPHA * (static_cast<float>(g_st_energy) - g_bg_energy);
        return;
    }

    // ── Onset detection ───────────────────────────────────────────────────────
    float ratio = static_cast<float>(g_st_energy) / (g_bg_energy + 1.0f);
    if (ratio >= ONSET_RATIO) {
        // Copy pre-trigger samples from ring buffer.
        uint16_t pre_start = g_pre_head - PRE_SAMPLES;
        for (uint16_t i = 0; i < PRE_SAMPLES; ++i) {
            g_window[i] = g_pre_buf[(pre_start + i) & (PRE_BUF_SIZE - 1)];
        }
        g_win_idx    = PRE_SAMPLES;
        g_capturing  = true;
        digitalWrite(STATUS_PIN, HIGH);
    } else {
        // Update background energy when quiet.
        g_bg_energy += BG_ALPHA * (static_cast<float>(g_st_energy) - g_bg_energy);
    }
}

// ── Serial framing ────────────────────────────────────────────────────────────
// Sends a 4-byte header followed by WINDOW_SAMPLES int16_t samples.
static void sendWindow() {
    uint16_t n = WINDOW_SAMPLES;

    Serial.write(PKT_KEYSTROKE);
    Serial.write(g_label);
    Serial.write(static_cast<uint8_t>(n & 0xFF));
    Serial.write(static_cast<uint8_t>((n >> 8) & 0xFF));

    // Send int16_t samples as little-endian byte pairs.
    for (uint16_t i = 0; i < WINDOW_SAMPLES; ++i) {
        int16_t s = g_window[i];
        Serial.write(static_cast<uint8_t>(s & 0xFF));
        Serial.write(static_cast<uint8_t>((s >> 8) & 0xFF));
    }
    digitalWrite(STATUS_PIN, LOW);
}

// ── Setup ─────────────────────────────────────────────────────────────────────
void setup() {
    Serial.begin(BAUD_RATE);
    pinMode(STATUS_PIN, OUTPUT);
    pinMode(MIC_PIN, INPUT);

    setADCPrescaler64();
    analogRead(MIC_PIN);  // discard first reading after prescaler change

    // Timer1 CTC, prescaler 8.
    TCCR1A = 0;
    TCCR1B = (1 << WGM12) | (1 << CS11);
    OCR1A  = T1_OCR;
    TCNT1  = 0;
    TIMSK1 = (1 << OCIE1A);

    Serial.write(PKT_READY);
}

// ── Main loop ─────────────────────────────────────────────────────────────────
void loop() {
    // Handle host commands.
    if (Serial.available()) {
        uint8_t cmd = static_cast<uint8_t>(Serial.read());
        if (cmd == PKT_LABEL) {
            // Next byte is the label.
            while (!Serial.available()) {}
            g_label = static_cast<uint8_t>(Serial.read());
        } else if (cmd == PKT_IDENT) {
            Serial.write(PKT_READY);
            Serial.write(static_cast<uint8_t>(SAMPLE_RATE_HZ & 0xFF));
            Serial.write(static_cast<uint8_t>((SAMPLE_RATE_HZ >> 8) & 0xFF));
        }
    }

    // Transmit completed window (outside ISR, no timing pressure).
    if (g_send_ready) {
        g_send_ready = false;
        sendWindow();
    }
}
