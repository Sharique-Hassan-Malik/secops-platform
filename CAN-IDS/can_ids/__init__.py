"""
CAN Bus Intrusion Detection System.

Detects anomalous message patterns in Controller Area Network traffic
captured via OBD-II or SocketCAN. Works offline on log files or inline
on a live SocketCAN interface.

Detection methods:
  - Frequency anomaly     : per-ID message rate deviation from baseline
  - Timing anomaly        : inter-arrival time outliers per ID
  - Replay attack         : repeated (ID, payload) sequences within tight windows
  - Payload anomaly       : byte-level statistical deviation per ID and position
  - Unknown ID            : CAN IDs absent from the baseline profile
"""

__version__ = "1.0.0"
