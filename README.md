# Email Verifier CLI

An all-in-one outreach utility for cold emailing.

CLI Flags Added:

  - --find - Switch to email finding mode
  - --domain - Domain for email finding
  - --first-name - First name for email finding

  - --last-name - Last name for email finding

  Usage Examples:

  Email Finding:
  python check_email.py --find --domain
  google.com --first-name John --last-name Doe

  Email Verification (unchanged):

  ```bash
  python check_email.py test@example.com
  python check_email.py test@example.com
  --no-apis
  ```

  Environment Setup:

  Add HUNTER_API_KEY=your_key_here to your .env
  file (example added to .env.example)

  API Priority:

  Hunter.io verifier runs first when available,
  falling back to Abstract/MailboxLayer if
  Hunter gives inconclusive results.


## APIs

[Abstract API](https://app.abstractapi.com/dashboard)

[HunterIO](https://hunter.io/dashboard)

- 50 credits per month (view [usage](https://hunter.io/usage))
