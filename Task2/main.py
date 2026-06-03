import sys
from caesar_cipher import caesar_encrypt, caesar_decrypt, display_cipher_table


def print_banner() -> None:
    banner = """
   ╔══════════════════════════════════╗
   ║        C A E S A R   C I P H E R ║
   ║    Basic Encryption & Decryption ║
   ╚══════════════════════════════════╝
    """
    print(banner)


def get_valid_shift() -> int:
    while True:
        try:
            shift_str = input("  Enter shift value (1-25): ").strip()
            shift = int(shift_str)
            if 1 <= shift <= 25:
                return shift
            print("  ⚠ Shift must be between 1 and 25. Try again.")
        except ValueError:
            print("  ⚠ Invalid input. Please enter an integer (1-25).")


def get_user_text() -> str:
    print("  Enter the text to encrypt/decrypt:")
    text = input("  > ").strip()
    if not text:
        print("  ⚠ No text entered. Using default: 'Hello, World!'")
        return "Hello, World!"
    return text


def main() -> None:

    print_banner()
    text = get_user_text()
    shift = get_valid_shift()

    # Process
    encrypted = caesar_encrypt(text, shift)
    decrypted = caesar_decrypt(encrypted, shift)

    # Display results
    print(f"\n  ┌─{'─' * 50}─┐")
    print(f"  │ {'Original text:':<20} {text:<28} │")
    print(f"  │ {'Shift value:':<20} {shift:<28} │")
    print(f"  ├─{'─' * 50}─┤")
    print(f"  │ {'ENCRYPTED:':<20} {encrypted:<28} │")
    print(f"  │ {'DECRYPTED:':<20} {decrypted:<28} │")
    print(f"  └─{'─' * 50}─┘")

    display_cipher_table(shift)

    # Quick test: verify decryption matches original
    if decrypted == text:
        print(f"  ✅ Success: Decrypted text matches original!\n")
    else:
        print(f"  ❌ Error: Decryption mismatch!\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n  Goodbye!\n")
        sys.exit(0)
