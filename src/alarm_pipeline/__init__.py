"""Alarm pipeline - turns PRTG notifications into AWS DevOps Agent investigations.

``payload`` parses PRTG notifications and derives priority and idempotency tokens;
it is standard-library only and safe to import anywhere. ``routing`` and ``handler``
need boto3, which the Lambda runtime provides.
"""
