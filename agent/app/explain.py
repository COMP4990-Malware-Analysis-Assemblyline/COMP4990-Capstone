def explain_route(route: str, filename: str) -> str:
    if route == "DEEP":
        return f"File {filename} routed to deep analysis due to higher risk indicators."
    return f"File {filename} routed to fast analysis due to low-risk indicators."
