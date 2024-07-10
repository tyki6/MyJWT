"""
All Environment variables
"""

import click
from questionary import Separator, Style

NOT_VALID_JWT = click.style("Enter a valid JWT!!!", fg="red", bold=True)
CHECK_DOCS = click.style(
    "Check Docs!!Your jwt have not a HS alg.",
    fg="red",
    bold=True,
)
NOT_CRAKED = click.style("JWT not cracked sorry. :'(", fg="red", bold=False)
CRACKED = click.style("JWT cracked, key is: ", fg="green", bold=False)
VALID_PAYLOAD = click.style(
    "Enter a Valid payload, Format: username=admin",
    fg="red",
    bold=False,
)
VALID_COOKIES = click.style(
    "Enter a Valid cookie, Format: username=admin",
    fg="red",
    bold=False,
)
VALID_DATA = click.style(
    "Enter a Valid data, Format: username=admin",
    fg="red",
    bold=False,
)
VALID_HEADER = click.style(
    "Enter a Valid header, Format: username=admin",
    fg="red",
    bold=False,
)
VALID_PAYLOAD_JSON = click.style(
    "Not a valid format for payload, send a json.",
    fg="red",
    bold=False,
)
NEW_JWT = click.style("new JWT: ", fg="green", bold=True)
VALID_SIGNATURE = click.style("Valid Signature!!", fg="green", bold=True)
INVALID_SIGNATURE = click.style("Incorrect signature!!", fg="red", bold=True)
CLIPBOARD = click.style("New jwt Copied to clipboard", fg="blue", bold=False)
# User interface
custom_style_fancy = Style(
    [
        ("qmark", "fg:#673ab7 bold"),  # token in front of the question
        ("question", "bold"),  # question text
        (
            "answer",
            "fg:#f44336 bold",
        ),  # submitted answer text behind the question
        (
            "pointer",
            "fg:#673ab7 bold",
        ),  # pointer used in select and checkbox prompts
        (
            "highlighted",
            "fg:#673ab7 bold",
        ),  # pointed-at choice in select and checkbox prompts
        ("selected", "fg:#cc5454"),  # style for a selected item of a checkbox
        ("separator", "fg:#cc5454"),  # separator in lists
        (
            "instruction",
            "",
        ),  # user instructions for select, rawselect, checkbox
        ("text", ""),  # plain text
        (
            "disabled",
            "fg:#858585 italic",
        ),  # disabled choices for select and checkbox prompts
    ],
)
# Summary
MAIN_SUMMARY_QUESTION = "What do you want to do?"
MAIN_SUMMARY_CHOICES_MODIFY = "Modify your jwt"
MAIN_SUMMARY_CHOICES_NONE_ALG = "Check None algorithm"
MAIN_SUMMARY_CHOICES_RSA_CONFUSION = "Check Rsa/Hmac confusion"
MAIN_SUMMARY_CHOICES_BRUTE_FORCE = "Brute-force your jwt to guess key(wordlist needed)"
MAIN_SUMMARY_CHOICES_SIGN = "Sign your jwt"
MAIN_SUMMARY_CHOICES_VERIFY = "Verify your key"
MAIN_SUMMARY_CHOICES_KID = "Kid injection"
MAIN_SUMMARY_CHOICES_JKU = "Jku bypass"
MAIN_SUMMARY_CHOICES_X5U = "X5u bypass"
MAIN_SUMMARY_CHOICES_QUIT = "Quit"

# Separator
SEPARATOR_MODIFY_JWT = Separator(
    "--------------------------- Modify your jwt ---------------------------",
)
SEPARATOR_VULNERABILITIES = Separator(
    "---------------------------- Vulnerabilities ----------------------------",
)
SEPARATOR_GUESS_KEY = Separator(
    "------------------------------ Guess key ------------------------------",
)
SEPARATOR_ADVANCED = Separator(
    "------------------------------- Advanced -------------------------------",
)
SEPARATOR_QUIT = Separator(
    "--------------------------------- Quit ---------------------------------",
)

# choices

MAIN_SUMMARY_CHOICES = [
    SEPARATOR_MODIFY_JWT,
    MAIN_SUMMARY_CHOICES_MODIFY,
    # vulnerability
    SEPARATOR_VULNERABILITIES,
    MAIN_SUMMARY_CHOICES_NONE_ALG,
    MAIN_SUMMARY_CHOICES_RSA_CONFUSION,
    # guess key
    SEPARATOR_GUESS_KEY,
    MAIN_SUMMARY_CHOICES_BRUTE_FORCE,
    MAIN_SUMMARY_CHOICES_SIGN,
    MAIN_SUMMARY_CHOICES_VERIFY,
    # advanced
    SEPARATOR_ADVANCED,
    MAIN_SUMMARY_CHOICES_KID,
    MAIN_SUMMARY_CHOICES_JKU,
    MAIN_SUMMARY_CHOICES_X5U,
    SEPARATOR_QUIT,
    MAIN_SUMMARY_CHOICES_QUIT,
]
MAIN_SUMMARY_PROMPT_PEM = "Please enter your public key (.pem)"
MAIN_SUMMARY_PROMPT_WORDLIST = "Please enter your wordlist (.txt)"
MAIN_SUMMARY_PROMPT_KEY = "Please enter your key"
MAIN_SUMMARY_PROMPT_INJECTION = "Please enter your injection"
MAIN_SUMMARY_PROMPT_JWKS = "Url of your jwks is stored (your external ip)"
# modify_summary
MODIFY_SUMMARY_QUESTION = "What do you want to do?"

SEPARATOR_HEADER = Separator(
    "---------------------------- Header ----------------------------",
)
SEPARATOR_PAYLOAD = Separator(
    "---------------------------- Payload ----------------------------",
)
MODIFY_SUMMARY_CHOICES_ADD_HEADER = "add header value"
MODIFY_SUMMARY_CHOICES_ADD_PAYLOAD = "add payload value"
MODIFY_SUMMARY_CHOICES_RETURN = "Return"

MODIFY_SUMMARY_PROMPT_VALUE = "Please enter a value"
MODIFY_SUMMARY_PROMPT_KEY = "Please enter a key"
