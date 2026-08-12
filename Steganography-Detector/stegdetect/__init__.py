"""
stegdetect — multi-method steganography detector.

Quick usage:
    from stegdetect.detector import detect
    result = detect("photo.png")
    print(result["verdict"])
"""

from stegdetect.detector import detect

__all__ = ["detect"]
