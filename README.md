# Two Factor Authentication with Flask and twilio

Two-Factor Authentication is a more secure way of logging in to a website. In addition to entering a password online, a user has to enter a random verification code generated at login time. This combination of passwords makes it easier to safeguard your applications.


## Installation

To install your application on your computer follow these steps:

1. Clone this repository.
2. Run `pip install -r requirements.txt` to import all the dependencies.
3. Add your twilio credentials to your shell environment. From the terminal, run
```
echo "export TWILIO_ACCOUNT_SID=<your sid>" >> ~/.bashrc
echo "export TWILIO_AUTH_TOKEN=<your auth token>" >> ~/.bashrc
```
4. Set your twilio phone number (PHONE_NUMBER) in the config.py  
5. Run the application with `python app.py`.
6. Go to `http://localhost:5000` in your address bar to connect to the application.

## How it works

There are three steps involved in building a two-factor authentication system.

* Collect the username, phone number, and the user's preferred method of contact.

* Next, Generate and send that password via a second (non-email/web) channel that an attacker is unlikely to have.

* Finally, compare our originally generated password against the submitted password.

