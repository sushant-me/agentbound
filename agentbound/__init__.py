"""agentbound — static detector for AI-agent tool-boundary bugs.

Detects the framework-side bug class of *tool shadowing*: reserved tool names,
last-wins tool registration, fail-open confirmation gates, and unauthenticated
agent CI dispatch. Each rule is grounded in a real, disclosed finding.
"""

__version__ = "0.1.9"
