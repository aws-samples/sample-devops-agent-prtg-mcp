"""PRTG MCP server - read-only PRTG tools for AWS DevOps Agent.

``tools`` holds the tool schema and is safe to import anywhere (standard library
only). ``prtg_client`` and ``handler`` require urllib3 and boto3, both of which
are present in the Lambda runtime.
"""
