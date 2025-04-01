# Password-Security-Toolkit

Advanced Password Security Toolkit is a Python-based application designed to help users create and manage secure passwords. It offers a range of features including validation against policies, strength analysis, breach checks, entropy calculation, and password generation. Additionally, it includes a simpler program dedicated to password strength checking.

## Table of Contents
1. [Features](#features)
2. [How It Works](#how-it-works)
3. [Password Policy](#password-policy)
4. [Dependencies](#dependencies)
5. [Requirements](#requirements)
6. [Installation](#installation)
7. [Usage](#usage)
8. [Simple Password Strength Checker](#simple-password-strength-checker)
9. [Password Breach Checker](#password-breach-checker)
10. [Entropy Calculator](#entropy-calculator)
11. [Strong Password Generator](#strong-password-generator)
12. [Main Function](#main-function)
13. [Example Outputs](#example-outputs)
14. [Future Enhancements](#future-enhancements)
15. [Contributing](#contributing)
16. [Acknowledgments](#acknowledgments)

## Features
- **Advanced Functionality**: 
  - Policy validation, strength analysis, breach detection, entropy calculation, and secure password generation.
- **Simple Password Strength Checker**: 
  - Focused on evaluating password strength using zxcvbn.

## How It Works

### Validation
1. Validates passwords against comprehensive policies:
   - Evaluates length, composition, and patterns.
   - Provides actionable feedback for improvements.

### Strength Analysis
1. Evaluates passwords using zxcvbn:
   - Assigns a score (0 to 4).
   - Delivers warnings about potential vulnerabilities.
   - Suggests ways to strengthen passwords.

### Breach Detection
1. Checks if passwords have been exposed in known data breaches using "Have I Been Pwned" API.
2. Flags compromised passwords and advises immediate replacement.

### Entropy Calculation
1. Calculates password entropy (measured in bits) based on:
   - Length.
   - Diversity of character types.
   - Predictability.
2. Presents a detailed report on entropy metrics.

### Password Generation
1. Creates random passwords with a minimum length of 12 characters.
2. Defaults to generating passwords of 16 characters if length is not specified, adhering to NIST guidelines for secure password practices.
3. Includes uppercase letters, lowercase letters, digits, and special characters to ensure strength.
4. Validates generated passwords for compliance with security policies.

## Password Policy

The program enforces a robust password policy to ensure high levels of security. The policy is designed to comply with established cybersecurity guidelines, including protection against SQL injection vulnerabilities. Each password is evaluated against the following criteria:

1. **Minimum Length**: 
   - Passwords must be at least 12 characters long to provide sufficient complexity.
2. **Composition Requirements**:
   - Uppercase Letters: At least one uppercase letter (A-Z).
   - Lowercase Letters: At least one lowercase letter (a-z).
   - Numbers: At least one numeric character (0-9).
   - Special Characters: At least one special symbol from the following set: ! @ # $ % ^ & * ( ) , . ? : " { } | < >.
3. **SQL Injection Prevention**:
   - Passwords must not contain characters commonly used in SQL injection attacks, such as: 
     - Single quote (')
     - Double quote (")
     - Backslash (\)
     - Semicolon (;)
     - Double dash (--)
4. **User Feedback**:
   - If a password does not meet one or more criteria, the program provides detailed feedback specifying which requirements were not fulfilled.

## Dependencies

The following modules are essential for the functionality of the advanced program:
- `hashlib` and `sha1`: Used for hashing algorithms, ensuring secure storage and handling of sensitive password data.
- `re` (Regular Expressions): Enforces password policies by detecting patterns and validating compliance with security rules.
- `requests`: Enables integration with external APIs like "Have I Been Pwned" for breach detection.
- `math`: Provides mathematical functions needed for entropy calculations, measuring password randomness and security.
- `random`: Used for generating random characters during password generation, ensuring diversity and unpredictability.
- `string`: Supplies character sets for password creation, including uppercase, lowercase letters, digits, and special symbols.
- `zxcvbn`: A powerful library for assessing password strength, providing actionable feedback and scoring based on real-world patterns.

## Requirements
- Python 3.x

## Installation

1. Clone the repository: 
   ```bash
   git clone https://github.com/yourusername/password-security-toolkit.git
2. Change into the project directory:
   ```bash
     cd password-security-toolkit
3. Install dependencies:
   ```bash
     pip install -r requirements.txt

## Usage
1. Run the toolkit:
   ```bash
     python password_toolkit.py
2. Choose an option from the menu:
  * Validate a password.
  * Analyze password strength.
  * Check for breaches.
  * Calculate entropy.
  * Generate a strong password.

## Simple Password Strength Checker
This program is a streamlined tool built with the zxcvbn library to evaluate password strength and provide actionable feedback. It's perfect for quick password strength analysis without additional features.

### Key Features:
  * Strength Score Ranges from 0 (very weak) to 4 (very strong)
  * Feedback Mechanism: Offers warnings about detected vulnerabilities and suggestions to improve password strength.
  * Dat-Driven Analysis: Uses patterns and real-world data to assess password robustness

### References: 
[zxcvbn Password Strength Estimator](https://github.com/dropbox/zxcvbn): Built by Dropbox, providing reliable evaluations based on common usage patterns and vulnerabilities.


## Password Breach Checker
This feature checks whether a password has been exposed in known data breaches by querying the "Have I Been Pwned" API. It ensures users avoid using compromised passwords to maintain security.

### Key Features:
  * API Integration: Utilizes the "Have I Been Pwned" API for checking against publicly available breach databases.
  * Efficient Querying: Leverages SHA1 hashing and prefix searching for secure, fast, and privacy-conscious password verification.
  * User Awareness: Alerts users if their password has been breached and recommends immediate replacement.

### References: 
[Have I Been Pwned API](https://haveibeenpwned.com/API/v3): A trusted service for checking password exposure.

## Entropy Calculator
This feature calculates the entropy of a password to measure its unpredictability and resistance to brute-force attacks. Password entropy is expressed in bits; higher entropy values indicate stronger and more secure passwords.

### Key Features:
  * Entropy Formula: Utilizes the Shannon entropy calculation: Entropy=Password Length×log⁡2(Character Set Size)Entropy=Password Length×log​~2~(Character Set Size)
  * Character Set Analysis: Evaluates the diversity of unique characters in the password to determine its Character Set Size.
  * Detailed Insights: Provides a quantifiable metric to assess password randomness and security.

### References:
* [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
* [Shannon Entropy - Wikipedia](https://en.wikipedia.org/wiki/Entropy_(information_theory))

## Strong Password Generator
This feature creates random, secure passwords that comply with NIST guidelines, ensuring they are resistant to brute-force attacks and meet modern security standards.

### Key Features:
  * Customizable Length: Generates passwords with a minimum length of 12 characters, adhering to strong password guidelines. The default length is 16 characters if unspecified.
  * Character Diversity: Includes uppercase letters, lowercase letters, digits, and special symbols while excluding characters commonly used in SQL injection attacks.
  * Standards-Compliant: Follows NIST Special Publication 800-63B recommendations for secure password creation.

### References:
* [NIST Special Publication 800-63B](https://pages.nist.gov/800-63-3/)
* [Shannon Entropy - Wikipedia](https://en.wikipedia.org/wiki/Entropy_(information_theory))

## Menu Function
The main function serves as the central hub for user interaction, offering a menu-based interface that allows users to access all features of the program seamlessly. It ensures a user-friendly experience by guiding users through the available tools and handling invalid inputs gracefully.

### Key Features:
  * Menu-Driven Navigation: Presents a clear menu with options for:
      1. Password policy validation.
      2. Strength evaluation.
      3. Breach detection.
      4. Entropy calculation.
      5. Strong password generation.
      6. Exiting the program.
  * Continuous Interaction: Loops until the user decides to exit, allowing multiple actions in a single session.
  * Error Handling:
      * Catches invalid choices and prompts the user for valid inputs.
      * Manages unexpected errors, ensuring the program runs smoothly.

## Example Outputs
### Validation Example:
  ```Plaintext
1. Check password policy
2. Check password strength
3. Check if password has been breached
4. Calculate password entropy
5. Generate a strong password
6. Exit

Choose an option (1-6): 1
```
#### Valid Password:
 ```Plaintext
Enter a password to check against policy: MySecurePass123!

Your password meets all policy requirements!
```
#### Invalid Password:
```Plaintext
Enter a password to check against policy: password

Policy Violations:
- Password must be at least 12 characters long.
- Password must include at least one uppercase letter.
- Password must include at least one number.
- Password must include at least one special character.
```

### Password Strength Example:
```Plaintext
--- Password Evaluation Menu ---
1. Check password policy
2. Check password strength
3. Check if password has been breached
4. Calculate password entropy
5. Generate a strong password
6. Exit

Choose an option (1–6): 2
```
#### Strong Password:
```Plaintext
Enter a password to check its strength: MySecurePass123!

Password Strength Score: 4/4
Suggestions:
(No suggestions necessary, this password is strong!)
```
#### Weak Password:
```Plaintext
Enter a password to check its strength: password

Password Strength Score: 0/4
Warning: This is a top-10 common password.
Suggestions:
- Add another word or two. Uncommon words are better.
```
### Password Breach Checker:
```Plaintext
--- Password Evaluation Menu ---
1. Check password policy
2. Check password strength
3. Check if password has been breached
4. Calculate password entropy
5. Generate a strong password
6. Exit

Choose an option (1–6): 3
```
#### Safe Password:
```Plaintext
Enter a password to check for breaches: MySecurePass123!

Breach Check: Password is safe.
```
### Breached Password:
```Plaintext
Enter a password to check for breaches: password

Breach Check: Password has been breached!
```
### Password Entropy Test:
```Plaintext
--- Password Evaluation Menu ---
1. Check password policy
2. Check password strength
3. Check if password has been breached
4. Calculate password entropy
5. Generate a strong password
6. Exit

Choose an option (1–6): 4
```
#### High Entropy Password:
```Plaintext
Enter a password to calculate its entropy: MySecurePass123!

Password Entropy: 60.92 bits
```
#### Low Entropy Password:
```plaintext
Enter a password to calculate its entropy: password

Password Entropy: 22.46 bits
```
### Password Generation
```Plaintext
--- Password Evaluation Menu ---
1. Check password policy
2. Check password strength
3. Check if password has been breached
4. Calculate password entropy
5. Generate a strong password
6. Exit

Choose an option (1-6): 5
```
#### Successful Password Generation:
```Plaintext
Enter desired password length (minimum 12): 24

Generated Strong Password: 9pjVeWK3}F5oGi:v6]rXULUx
```
#### Invalid Password Length:
```Plaintext
Enter desired password length (minimum 12): 10

Error: Password length must be at least 12 characters.
```

### Exiting Program
```Plaintext
--- Password Evaluation Menu ---
1. Check password policy
2. Check password strength
3. Check if password has been breached
4. Calculate password entropy
5. Generate a strong password
6. Exit

Choose an option (1-6): 6

Exiting program.
```

## Future Enhancements
The toolkit is designed to evolve and adapt to new security challenges. Planned updates include:
* Advanced Breach Detection:
  * Display detailed breach information, such as the number of exposures and breach sources, through enhanced API integration.
* Entropy Visualization:
  * Add graphical representations of entropy values to make password randomness more understandable for users.
* Custom Policy Settings:
  * Allow users to customize password validation criteria, such as minimum length, required characters, and restricted patterns.

## Contributing
Contributions to the Advanced Password Security Toolkit are always welcome. Here’s how you can contribute:
1. **Fork the Repository**: Create a personal copy of this repository by clicking the "Fork" button on GitHub.
2. **Clone the Repository**: Download your forked version to your local machine:
   ```bash
   git clone https://github.com/Toast-stack/Password-Security-Toolkit.git
   ```
3. **Create a Branch**: Make a new branch for your feature or bug fix:
   ```bash
   git checkout -b feature-name
   ```
4. **Commit Your Changes**: Make and commit your changes with a detailed commit message:
   ```bash
   git commit -m "Add description of the feature or fix"
   ```
5. **Push to GitHub**: Push your changes to your repository:
   ```bash
   git push origin feature-name
   ```
6. **Open a Pull Request**: Submit a pull request to the original repository. Ensure your pull request includes a detailed description of the changes you've made.

Please follow clean coding practices and document your contributions thoroughly. Thank you for helping improve this project!

## Acknowledgments
* **Dropbox**: For providing the zxcvbn library, which powers the password strength estimation feature. [GitHub Repository](https://github.com/dropbox/zxcvbn)
* **Troy Hunt**: For creating the "Have I Been Pwned" API, an invaluable resource for checking password breaches. [API Documentation](https://haveibeenpwned.com/API/v3)
* **OWASP**: For their extensive resources on authentication best practices, including password management guidelines. [Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
* **NIST**: For publishing the SP 800-63B guidelines that inspired the password generation feature. [NIST SP 800-63B](https://pages.nist.gov/800-63-3/)
* **Shannon Entropy Concept**: For providing the foundation for entropy calculation and understanding password randomness. [Wikipedia](https://en.wikipedia.org/wiki/Entropy_(information_theory))
