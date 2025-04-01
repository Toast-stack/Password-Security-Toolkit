# Imports the necessary modules for password evaluations and for generation of new passwords
from hashlib import sha1
import hashlib
import re
from urllib import response # This is used for enforcing password policies using regular expressions
import requests # Used for interacting with external APIs
import math # Used for entropy calculations
import random # Used for generating random characters in strong passwords
import string # Used for creating character sets for password Generation
from zxcvbn import zxcvbn # Used for assessing the strength of the passwords

def enforce_password_policy(password):
    """
    Enforces basic password policies:
    * Minimum length
    * Inclusion of uppercase, lowercase, numbers, and special characters
    Returns a list of the violations, or returns an empty list if the password meets the requirements
    
    References:
    - SQL Injection Best Practices: OWASP SQL Injection Prevention Cheat Sheet
      https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
    """
    policies = {
        "length": len(password) >= 12, # Used to check if the password is 12 characters or more
        "uppercase": bool(re.search(r"[A-Z]", password)), # Used to check for uppercase letters
        "lowercase": bool(re.search(r"[a-z]", password)), # Used to check for lowercase letters
        "digit": bool(re.search(r"[0-9]", password)), # Used to check for numeric digits
        "special": bool(re.search(r"[!@#$%^&*(),.?\:{}|<>]", password)), # Used to check for special characters\
        "no_sql_injection": not bool(re.search(r"[\'\";\\-]", password)) # Used to reject the use of SQL-injection-prone Characters
        }

    feedback = [] # List used for storing feedback messages for violations

    if not policies["length"]:
        feedback.append("Password must be at least 12 characters long.")
    if not policies["uppercase"]:
        feedback.append("password must include at least one uppercase letter.")
    if not policies["lowercase"]:
        feedback.append("password must include at least one lowercase letter.")
    if not policies["digit"]:
        feedback.append("password must include at least one number.")
    if not policies["special"]:
        feedback.append("password must include at least one special character.")
    if not policies["no_sql_injection"]:
        feedback.append("password must not contain SQL injection prone characters (' \" ; -).")
    return feedback

# Password Strength Checker
def check_password_strength(password):
    """
    Analyzes the strength of a given password using the zxcvbn library.
    Returns a numerical score (0-4) and feedback for improvement.

    References:
    - zxcvbn Password Strength Estimator (GitHub)
      https://github.com/dropbox/zxcvbn
    """
    result = zxcvbn(password) # Perform analysis on the password
    
    score = result['score'] # Extract score: 0 (weak) to 4 (strong)
    
    feedback = result['feedback'] # Extracts feedback details for improvement

    return score, feedback

# Breach checker
def check_breach(password):
    """
    Checks if the password has been exposed in a data breach.
    Queries the Have I been Pwned API using SHA1 hash of the password.
    Returns True if breached, False otherwise.

    References:
    - Have I Been Pwned API Documentation
      https://haveibeenpwned.com/API/v3
    - Why SHA-1 is used in this context: 
      https://haveibeenpwned.com/Passwords
    """
    try:
        # Generate SHA-1 hash of the password
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        
        # Extract the first 5 characters for the API query
        prefix = sha1_hash[:5]
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        
        # Send request to the API
        response = requests.get(url, timeout=10)
        response.raise_for_status()  # Raise an error for HTTP issues
        
        # Check if the remaining hash exists in the response
        if sha1_hash[5:] in response.text:
            return True  # Password has been breached
        return False  # Password is safe
    
    except requests.exceptions.RequestException as e:
        print(f"Error: Unable to connect to the Have I Been Pwned API. Details: {e}")
        return False

# Entropy Calculator
def calculate_entropy(password):
    """
    Calculates the entropy of a password.
    Entropy measures how unpredictable a password is, in bits.
    Higher entropy indicates stronger security.

    References:
    - Password Entropy: OWASP Authentication Cheat Sheet
      https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
    - Shannon Entropy Calculation:
      https://en.wikipedia.org/wiki/Password_strength#Entropy_as_a_measure
    """
    charset_size = len(set(password)) # Count the number of unique characters in the password

    entropy = len(password) * math.log2(charset_size) #entropy formula

    return entropy

def generate_strong_password(length=16):
    """
    Generates a random, strong password with the specified length.
    Excludes characters commonly used in SQL Injection attacks.

    References:
    - Strong Password Guidelines: NIST Special Publication 800-63B
      https://pages.nist.gov/800-63-3/sp800-63b.html
    """

    if length < 12: # Ensure minimum length for strong passwords

        raise ValueError("Password length must be at least 12 characters.")

    # Define a character set excluding SQL injection-prone characters
    characters = string.ascii_letters + string.digits + "!@#$%^&*()_+[]{}|:,.<>?/="
    password = ''.join(random.choice(characters) for _ in range(length))

    return password

# Main Menu Function
def main():
    """
    Displays the main menu for user interaction.
    Allows users to choose various password evaluation and generation services.
    Loops until the user decides to exit.
    """
    while True:
        # Display menu options
        print("\n--- Password Evaluation Menu ---")
        print("1. Check password policy")  # Option to enforce password policies
        print("2. Check password strength")  # Option to evaluate password strength
        print("3. Check if password has been breached")  # Option to query Have I Been Pwned
        print("4. Calculate password entropy")  # Option to calculate entropy
        print("5. Generate a strong password")  # Option to generate a random, strong password
        print("6. Exit")  # Option to exit the program

        try:
            # Get user choice
            choice = input("\nChoose an option (1-6): ").strip()

            # Validate choice and handle menu options
            if choice == "1":  # Check password policy
                password = input("\nEnter a password to check against policy: ").strip()
                feedback = enforce_password_policy(password)
                if feedback:
                    print("\nPolicy Violations:")
                    for item in feedback:
                        print(f"- {item}")
                else:
                    print("\nYour password meets all policy requirements!")

            elif choice == "2":  # Check password strength
                password = input("\nEnter a password to check its strength: ").strip()
                score, feedback = check_password_strength(password)
                print(f"\nPassword Strength Score: {score}/4")
                if feedback['warning']:
                    print(f"Warning: {feedback['warning']}")
                print("Suggestions:")
                for suggestion in feedback['suggestions']:
                    print(f"- {suggestion}")

            elif choice == "3":  # Check if password has been breached
                password = input("\nEnter a password to check for breaches: ").strip()
                breached = check_breach(password)
                print(f"\nBreach Check: {'Password has been breached!' if breached else 'Password is safe.'}")

            elif choice == "4":  # Calculate password entropy
                password = input("\nEnter a password to calculate its entropy: ").strip()
                entropy = calculate_entropy(password)
                print(f"\nPassword Entropy: {entropy:.2f} bits")

            elif choice == "5":  # Generate strong password
                try:
                    length = int(input("\nEnter desired password length (minimum 12): ").strip())
                    if length < 12:
                        raise ValueError("Password length must be at least 12 characters.")
                    strong_password = generate_strong_password(length)
                    print(f"\nGenerated Strong Password: {strong_password}")
                except ValueError as e:
                    print(f"\nError: {e}")

            elif choice == "6":  # Exit the program
                print("\nExiting program.")
                break

            else:  # Handle invalid choices
                print("\nInvalid choice! Please select a valid option.")

        except Exception as e:
            print(f"\nAn unexpected error occurred: {e}")

if __name__ == "__main__":
    main()