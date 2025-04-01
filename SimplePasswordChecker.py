from zxcvbn import zxcvbn

def check_password_strength(password):
    result = zxcvbn(password)
    score = result['score']

    feedback = result['feedback']
    return score, feedback

def main():
    password = input("Enter a password to check its strength: ")
    score, feedback = check_password_strength(password)
    print(f"\nPassword Strength Score: {score}/4") # 0 being the weakest and 4 being the strongest

    if feedback['warning']:
        print(f"Warning: {feedback['warning']}")

    print("Suggestions: ")
    for suggestion in feedback['suggestions']:
        print(f"- {suggestion}")

if __name__ == "__main__":
    main()