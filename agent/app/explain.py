from .policy import get_policy_for_route


def explain_route(route: str, filename: str) -> str:
    policy = get_policy_for_route(route)

    if route == "FAST":
        return (
            f"File {filename} routed to FAST for rapid static triage under policy "
            f"{policy['policy_id']} ({policy['display_name']})."
        )
    if route == "DEEP":
        return (
            f"File {filename} routed to DEEP for expanded analysis under policy "
            f"{policy['policy_id']} ({policy['display_name']}) based on suspicious indicators."
        )
    if route == "HUMAN_REVIEW":
        return (
            f"File {filename} routed to HUMAN_REVIEW under policy "
            f"{policy['policy_id']} ({policy['display_name']}) due to high-risk or uncertain signals."
        )

    return (
        f"File {filename} routed using fallback policy {policy['policy_id']} "
        f"({policy['display_name']})."
    )
