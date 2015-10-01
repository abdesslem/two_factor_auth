# Two Factor Authentication with Flask and twilio

Two-Factor Authentication is a more secure way of logging in to a website. In addition to entering a password online, a user has to enter a random verification code generated at login time. This combination of passwords makes it easier to safeguard your applications.


## Installation

To install your application on your computer follow these steps:

1. Clone this repository.
2. Create a virtual environment and activate it.
3. Run `pip install -r requirements.txt` to import all the dependencies.
4. Run the application with `python app.py`.
5. Go to `http://localhost:5000` in your address bar to connect to the application.

## Usage

There are three steps involved in building a two-factor authentication system.

* We want to collect the username, phone number, and the user's preferred method of contact.

* Next, we want to generate and send that password via a second (non-email/web) channel that an attacker is unlikely to have.

* Finally, compare our originally generated password against the submitted password.

