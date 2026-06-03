import string
def caesar_encrypt(text: str, shift: int) -> str:
    
    result: list[str] = []
    for char in text:
        if char.isupper():
            result.append(chr((ord(char) - ord('A') + shift) % 26 + ord('A')))
        elif char.islower():
            result.append(chr((ord(char) - ord('a') + shift) % 26 + ord('a')))
        else:
            result.append(char)
    return ''.join(result)


def caesar_decrypt(text: str, shift: int) -> str:

    return caesar_encrypt(text, -shift)


def display_cipher_table(shift: int) -> None:
    
    lower = string.ascii_lowercase
    shifted_lower = caesar_encrypt(lower, shift)

    header = f"  {' '.join(lower)}"
    separator = "  " + "-" * (len(lower) * 2 - 1)
    shifted = f"  {' '.join(shifted_lower)}"

    print("\nCipher substitution table:")
    print(header)
    print(separator)
    print(shifted)
    print()
