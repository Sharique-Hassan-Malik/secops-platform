"""Classify keystrokes from a recording, with no hardware attached.

The firmware does the segmentation: it detects a key press and streams one
fixed window per keystroke. That is the right design on the device, and it left
the host side unable to analyse anything it had not captured live — which meant
the attack could not be demonstrated, tested, or run against a recording
somebody else made.

This is the missing half: energy-onset segmentation over a recorded waveform,
producing the same fixed windows the firmware would have sent, so the existing
feature extractor and model work unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import numpy as np

from features import SAMPLE_RATE, MFCCExtractor

WINDOW_MS = 50.0          # what the firmware sends per keystroke
MIN_GAP_MS = 60.0         # two presses closer than this are one press
ONSET_FACTOR = 4.0        # energy multiple over the noise floor to call an onset


@dataclass
class Segment:
    index: int
    start_sample: int
    samples: np.ndarray

    @property
    def start_seconds(self) -> float:
        return self.start_sample / SAMPLE_RATE


def segment_keystrokes(
    samples: np.ndarray,
    sample_rate: int = SAMPLE_RATE,
    *,
    onset_factor: float = ONSET_FACTOR,
    window_ms: float = WINDOW_MS,
    min_gap_ms: float = MIN_GAP_MS,
) -> list[Segment]:
    """Find keystroke onsets by short-time energy and cut fixed windows.

    A keystroke is a transient: the press is a sharp rise in energy over a
    quiet floor. Thresholding against the *median* frame energy rather than the
    mean matters — the mean is dragged up by the very transients being looked
    for, so a recording with many keystrokes would raise its own threshold
    until it found none.
    """
    signal = np.asarray(samples, dtype=np.float32)
    if signal.ndim > 1:
        signal = signal.mean(axis=1)
    if signal.size == 0:
        return []

    frame = max(1, int(sample_rate * 0.005))          # 5 ms energy frames
    frames = signal[: len(signal) // frame * frame].reshape(-1, frame)
    energy = (frames ** 2).mean(axis=1)
    if energy.size == 0:
        return []

    floor = float(np.median(energy)) or float(energy.mean()) or 1e-9
    threshold = floor * onset_factor

    window = int(sample_rate * window_ms / 1000)
    min_gap = int(sample_rate * min_gap_ms / 1000)

    segments: list[Segment] = []
    last_onset = -min_gap
    for index, value in enumerate(energy):
        if value < threshold:
            continue
        start = index * frame
        if start - last_onset < min_gap:
            continue
        chunk = signal[start:start + window]
        if chunk.size < window:
            chunk = np.pad(chunk, (0, window - chunk.size))
        segments.append(Segment(len(segments), start, chunk.astype(np.int16)))
        last_onset = start

    return segments


def load_wav(path: str | Path) -> tuple[np.ndarray, int]:
    """Read a WAV file as int16 mono, without a third-party audio library."""
    import wave

    with wave.open(str(path), "rb") as handle:
        rate = handle.getframerate()
        channels = handle.getnchannels()
        raw = handle.readframes(handle.getnframes())

    data = np.frombuffer(raw, dtype=np.int16)
    if channels > 1:
        data = data.reshape(-1, channels).mean(axis=1).astype(np.int16)
    return data, rate


def classify_recording(
    audio: str | Path | np.ndarray,
    model_path: str | Path,
    sample_rate: int = SAMPLE_RATE,
) -> list[tuple[str, float]]:
    """Return (character, confidence) for every keystroke found in *audio*."""
    import joblib

    if isinstance(audio, (str, Path)):
        samples, sample_rate = load_wav(audio)
    else:
        samples = np.asarray(audio)

    bundle = joblib.load(str(model_path))
    pipeline, keys = bundle["pipeline"], bundle["keys"]
    extractor = MFCCExtractor(sample_rate=sample_rate)

    predictions: list[tuple[str, float]] = []
    for segment in segment_keystrokes(samples, sample_rate):
        features = extractor.extract(segment.samples).reshape(1, -1)
        index = int(pipeline.predict(features)[0])
        confidence = float(pipeline.predict_proba(features)[0].max())
        character = keys[index - 1] if 1 <= index <= len(keys) else "?"
        predictions.append((character, confidence))
    return predictions
