from math import log2


def calculate_entropy(filepath: str) -> float:
    """Return Shannon entropy for a file in bits per byte.

    Entropy is a simple way to describe how random-looking data is. Plain,
    structured text usually has lower entropy because the same characters repeat
    often. Encrypted, compressed, or random bytes usually have high entropy,
    approaching 8 bits per byte.
    """
    with open(filepath, "rb") as file:
        data = file.read()

    if not data:
        return 0.0

    frequencies = [0] * 256
    for byte in data:
        frequencies[byte] += 1

    entropy = 0.0
    data_length = len(data)
    for count in frequencies:
        if count == 0:
            continue
        probability = count / data_length
        entropy -= probability * log2(probability)

    return entropy
