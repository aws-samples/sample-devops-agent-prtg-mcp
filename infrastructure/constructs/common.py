"""Small helpers shared by the stacks."""

from __future__ import annotations

from typing import Final

from aws_cdk import aws_logs as logs

#: Day count to CDK's ``RetentionDays``. The enum members are symbolic
#: (``ONE_MONTH``, ``THREE_MONTHS``) rather than numeric, so a mapping is needed to
#: keep ``observability.log_retention_days`` expressed in plain days - which is how
#: retention policies are actually written down.
#:
#: Keys are exactly the values CloudWatch Logs accepts, and
#: ``ObservabilityConfig.validate`` rejects anything not listed here, so an invalid
#: value fails during configuration validation with a helpful message rather than
#: as a KeyError during synthesis.
RETENTION_BY_DAYS: Final[dict[int, logs.RetentionDays]] = {
    1: logs.RetentionDays.ONE_DAY,
    3: logs.RetentionDays.THREE_DAYS,
    5: logs.RetentionDays.FIVE_DAYS,
    7: logs.RetentionDays.ONE_WEEK,
    14: logs.RetentionDays.TWO_WEEKS,
    30: logs.RetentionDays.ONE_MONTH,
    60: logs.RetentionDays.TWO_MONTHS,
    90: logs.RetentionDays.THREE_MONTHS,
    120: logs.RetentionDays.FOUR_MONTHS,
    150: logs.RetentionDays.FIVE_MONTHS,
    180: logs.RetentionDays.SIX_MONTHS,
    365: logs.RetentionDays.ONE_YEAR,
    400: logs.RetentionDays.THIRTEEN_MONTHS,
    545: logs.RetentionDays.EIGHTEEN_MONTHS,
    731: logs.RetentionDays.TWO_YEARS,
    1096: logs.RetentionDays.THREE_YEARS,
    1827: logs.RetentionDays.FIVE_YEARS,
    3653: logs.RetentionDays.TEN_YEARS,
}


def retention_for(days: int) -> logs.RetentionDays:
    """Translate a day count into CDK's ``RetentionDays``.

    Raises:
        KeyError: if ``days`` is not a value CloudWatch Logs accepts. Configuration
            validation should have caught this first; reaching here means the
            validator and this mapping have fallen out of step.
    """
    try:
        return RETENTION_BY_DAYS[days]
    except KeyError as exc:
        raise KeyError(
            f"{days} is not a retention period CloudWatch Logs supports. Valid values: "
            f"{', '.join(str(d) for d in sorted(RETENTION_BY_DAYS))}."
        ) from exc
