## Bug Pattern

Calling devm_add_action_or_reset(dev, cleanup, data) and then, on non-zero return, manually invoking the same cleanup(data). Since devm_add_action_or_reset automatically calls the action on registration failure, the explicit cleanup call causes the cleanup to run twice (double free/destroy of resources managed by the cleanup).

Example anti-pattern:
if (devm_add_action_or_reset(dev, cleanup, data)) {
    cleanup(data);  // BUG: already called by devm_add_action_or_reset on failure
    return NULL;
}
