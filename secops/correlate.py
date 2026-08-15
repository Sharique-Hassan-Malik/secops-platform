"""Rules that fire across sensors — the reason these ten live in one repo.

A single sensor's answer is rarely decisive. Obfuscated bytecode is suspicious;
an image with a hidden payload is suspicious; the *same upload* being both is a
different claim entirely, and no individual tool can make it because no
individual tool sees the other's output.

Every rule here needs at least two sensors to agree, or one sensor to repeat
itself in a way a single observation cannot express. A rule that restates what
one sensor already said would just be that sensor's severity with extra steps.

Rules are plain functions over a list of events. They return alerts, they never
mutate, and each one names the events it fired on so an analyst can disagree
with it.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Callable, Iterable

from .core.event import Alert, Category, Event, Severity

Rule = Callable[[list[Event]], list[Alert]]

_RULES: list[tuple[str, Rule]] = []


def rule(name: str) -> Callable[[Rule], Rule]:
    def register(fn: Rule) -> Rule:
        _RULES.append((name, fn))
        return fn
    return register


def _by_entity(events: Iterable[Event]) -> dict[str, list[Event]]:
    grouped: dict[str, list[Event]] = defaultdict(list)
    for event in events:
        if event.entity:
            grouped[event.entity].append(event)
    return grouped


@rule("multi-sensor-agreement")
def multi_sensor_agreement(events: list[Event]) -> list[Alert]:
    """Two or more independent sensors flag the same thing at MEDIUM or above.

    Independence is the point. Two findings from one sensor are one opinion
    expressed twice; two sensors looking at different properties of the same
    artifact and both objecting is the signal that survives a false-positive
    review.
    """
    alerts = []
    for entity, group in _by_entity(events).items():
        serious = [e for e in group if e.severity >= Severity.MEDIUM]
        sensors = {e.sensor for e in serious}
        if len(sensors) < 2:
            continue
        worst = max(e.severity for e in serious)
        escalated = _escalate(worst)
        alerts.append(
            Alert(
                rule="multi-sensor-agreement",
                severity=escalated,
                entity=entity,
                description=(
                    f"{len(sensors)} sensors independently flagged {entity}: "
                    f"{', '.join(sorted(sensors))}. Escalated from "
                    f"{worst.value} to {escalated.value}."
                ),
                events=serious,
            )
        )
    return alerts


@rule("hidden-payload-in-hostile-artifact")
def hidden_payload_in_hostile_artifact(events: list[Event]) -> list[Alert]:
    """Evasion and a hostile artifact on the same entity.

    Concealment plus payload is a different story from either alone: it implies
    intent to get past exactly the kind of scanning being done here.
    """
    alerts = []
    for entity, group in _by_entity(events).items():
        evasion = [e for e in group if e.category is Category.EVASION]
        hostile = [e for e in group if e.category in (Category.MALWARE, Category.AVAILABILITY)]
        if not (evasion and hostile):
            continue
        # Both halves must come from different sensors. One sensor reporting
        # concealment *and* hostility has simply given its own verdict twice,
        # and restating it as a correlation would be an alert that adds nothing
        # but a higher severity.
        if {e.sensor for e in evasion} == {e.sensor for e in hostile} and \
                len({e.sensor for e in [*evasion, *hostile]}) == 1:
            continue
        alerts.append(
            Alert(
                rule="hidden-payload-in-hostile-artifact",
                severity=Severity.CRITICAL,
                entity=entity,
                description=(
                    f"{entity} carries concealed content ({evasion[0].sensor}) *and* "
                    f"is itself hostile ({hostile[0].sensor}). Concealment implies "
                    f"the payload was meant to survive inspection."
                ),
                events=[*evasion, *hostile],
            )
        )
    return alerts


@rule("recon-then-exploit")
def recon_then_exploit(events: list[Event]) -> list[Alert]:
    """The same origin fingerprints, then attacks.

    Either alone is background noise on any internet-facing host. In sequence
    from one origin they are an operator, not a scanner sweep.
    """
    alerts = []
    for entity, group in _by_entity(events).items():
        ordered = sorted(group, key=lambda e: e.timestamp)
        recon = [e for e in ordered if e.category is Category.RECON]
        exploit = [e for e in ordered if e.category is Category.EXPLOIT]
        if not (recon and exploit):
            continue
        if recon[0].timestamp > exploit[-1].timestamp:
            continue  # attacked first, fingerprinted later — not this pattern
        alerts.append(
            Alert(
                rule="recon-then-exploit",
                severity=Severity.HIGH,
                entity=entity,
                description=(
                    f"{entity} was fingerprinted ({recon[0].sensor}) before "
                    f"attacking ({exploit[0].sensor}) — reconnaissance followed "
                    f"by exploitation from one origin."
                ),
                events=[recon[0], *exploit],
            )
        )
    return alerts


@rule("sustained-intrusion")
def sustained_intrusion(events: list[Event]) -> list[Alert]:
    """One sensor reporting intrusion repeatedly against one entity.

    The exception to the two-sensor rule, and the reason for it: a single
    injected CAN frame is noise, forty of them against one arbitration ID is an
    attack in progress. Volume is information a per-event severity cannot
    carry.
    """
    threshold = 10
    alerts = []
    for entity, group in _by_entity(events).items():
        intrusions = [e for e in group if e.category is Category.INTRUSION]
        if len(intrusions) < threshold:
            continue
        alerts.append(
            Alert(
                rule="sustained-intrusion",
                severity=Severity.HIGH,
                entity=entity,
                description=(
                    f"{len(intrusions)} intrusion events against {entity} in one "
                    f"capture — sustained activity, not an isolated anomaly."
                ),
                events=intrusions[:threshold],
            )
        )
    return alerts


@rule("simulated-attack-went-undetected")
def simulated_attack_went_undetected(events: list[Event]) -> list[Alert]:
    """A red-team sensor succeeded and no blue-team sensor noticed.

    This is a finding about the *detection stack*, not the target. Running the
    simulators alongside the detectors is only worth doing if a silent success
    is reported as a gap rather than as a clean result.
    """
    simulated = [
        e for e in events
        if e.category is Category.SIDE_CHANNEL and e.severity >= Severity.MEDIUM
    ]
    if not simulated:
        return []
    detectors = {
        e.sensor for e in events
        if e.category in (Category.INTRUSION, Category.EXFILTRATION)
        and e.severity >= Severity.MEDIUM
    }
    if detectors:
        return []
    return [
        Alert(
            rule="simulated-attack-went-undetected",
            severity=Severity.MEDIUM,
            entity=simulated[0].entity or "detection stack",
            description=(
                f"{simulated[0].sensor} recovered data through a side channel and "
                f"no monitoring sensor raised anything. The gap is in the "
                f"detection coverage, not in the target."
            ),
            events=simulated,
        )
    ]


def _escalate(severity: Severity) -> Severity:
    order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    return order[min(order.index(severity) + 1, len(order) - 1)]


def rules() -> list[str]:
    return [name for name, _ in _RULES]


def correlate(events: list[Event], *, only: list[str] | None = None) -> list[Alert]:
    """Run every rule over the events, most severe alert first."""
    wanted = set(only) if only else None
    alerts: list[Alert] = []
    for name, fn in _RULES:
        if wanted is not None and name not in wanted:
            continue
        alerts.extend(fn(events))
    return sorted(alerts, key=lambda a: -a.severity.rank)
