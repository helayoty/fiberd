"""The one exception fiberd.template raises for a rule it enforces."""


class TemplateError(RuntimeError):
    """A rule of the template contract was broken. The message names the rule and the fix."""
