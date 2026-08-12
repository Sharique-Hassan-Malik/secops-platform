"""
infer.py — real-time keystroke classification using a trained model.

Streams keystroke windows from the Arduino, extracts MFCC features and
classifies each keystroke using the saved sklearn pipeline. Prints the
predicted key character and confidence to stdout.

Usage
-----
    python infer.py --port /dev/ttyACM0 [--model data/features/model.pkl]
"""

from __future__ import annotations

import argparse
import sys
import time

import joblib
import numpy as np

from features import MFCCExtractor
from transport import AcousticTransport, Keystroke


def run_inference(port: str, baud: int, model_path: str) -> None:
    bundle    = joblib.load(model_path)
    pipeline  = bundle["pipeline"]
    keys      = bundle["keys"]
    extractor = MFCCExtractor()

    print(f"Model loaded. Classes: {' '.join(keys)}")
    print("Listening for keystrokes… (Ctrl+C to stop)\n")

    def on_keystroke(ks: Keystroke) -> None:
        feat   = extractor.extract(ks.samples).reshape(1, -1)
        pred   = pipeline.predict(feat)[0]
        proba  = pipeline.predict_proba(feat)[0]
        conf   = float(proba.max()) * 100.0
        key    = keys[pred - 1] if 1 <= pred <= len(keys) else "?"
        ts     = time.strftime("%H:%M:%S")
        print(f"[{ts}]  →  '{key}'  ({conf:.1f}% confidence)")

    with AcousticTransport(port, baud) as t:
        rate = t.identify()
        print(f"Firmware sample rate: {rate} Hz")
        t.on_keystroke(on_keystroke)
        t.start()
        try:
            while True:
                time.sleep(0.1)
        except KeyboardInterrupt:
            pass

    print("\nStopped.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Real-time keystroke classifier")
    parser.add_argument("--port",  required=True)
    parser.add_argument("--baud",  type=int, default=500_000)
    parser.add_argument("--model", default="data/features/model.pkl")
    args = parser.parse_args()

    run_inference(args.port, args.baud, args.model)


if __name__ == "__main__":
    main()
