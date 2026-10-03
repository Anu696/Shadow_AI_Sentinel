def redact_data(text, findings):

    for item in sorted(
        findings,
        key=lambda x: x["start"],
        reverse=True
    ):

        category = item["category"]

        replacement = f"[REDACTED_{category.upper()}]"

        text = (
            text[:item["start"]]
            + replacement
            + text[item["end"]:]
        )

    return text