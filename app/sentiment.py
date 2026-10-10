
POSITIVE_WORDS = {
    "happy", "good", "great", "excellent", "love",
    "wonderful", "amazing", "helpful", "thankful",
    "excited", "success", "best", "awesome"
}

NEGATIVE_WORDS = {
    "sad", "bad", "terrible", "hate", "angry",
    "awful", "worst", "disappointed", "useless",
    "failure", "upset", "annoying", "poor"
}


def analyze_sentiment(text: str) -> dict:
    """
    Basic rule-based sentiment analysis.
    Returns positive, negative, or neutral sentiment.
    """

    words = text.lower().split()

    positive_count = sum(
        1 for word in words
        if word.strip(".,!?;:()\"'") in POSITIVE_WORDS
    )

    negative_count = sum(
        1 for word in words
        if word.strip(".,!?;:()\"'") in NEGATIVE_WORDS
    )

    if positive_count > negative_count:
        sentiment = "positive"
    elif negative_count > positive_count:
        sentiment = "negative"
    else:
        sentiment = "neutral"

    return {
        "sentiment": sentiment,
        "positive_words": positive_count,
        "negative_words": negative_count
    }
