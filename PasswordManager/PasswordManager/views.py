from flask import Flask
from PasswordManager import app

@app.route('/')
@app.route('/home')
def home():
    return "Hello Flask!"
