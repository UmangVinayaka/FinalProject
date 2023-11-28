import os
import re

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///calendar.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response
    

@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    result = db.execute(
        "SELECT symbol, name, SUM(shares) AS count, price, SUM(price * shares) as price_sum FROM transactions WHERE user_id = ? GROUP BY symbol HAVING count > 0",
        session["user_id"],
    )
    holdings = db.execute(
        "SELECT cash FROM users WHERE id = :user_id", user_id=session["user_id"]
    )
    grand_total = holdings[0]["cash"]
    print(holdings)

    for row in result:
        price = lookup(row["symbol"])["price"]
        shares = row["count"]
        grand_total += price * shares
    return render_template(
        "index.html",
        result=result,
        holdings=holdings[0]["cash"],
        grand_total=grand_total,
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    # get the symbol that user has submitted by accessing the form data in the request
    # lookup() returns a dictionary with information about the stock
    if request.method == "POST":
        symbol = request.form.get("symbol")
        if symbol is None:
            return apology("Invalid symbol")
        stock = lookup(symbol)
        if stock is None:
            return apology("Invalid symbol")
        return render_template("quoted.html", stock=stock)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        # validation
        if not request.form.get("username"):
            return apology("username must be provided")
        if not request.form.get("password"):
            return apology("password must be provided")
        if not request.form.get("confirmation"):
            return apology("confirmation must be provided")
        if request.form.get("password") != request.form.get("confirmation"):
            return apology("password does not match")

        # personal touch: require secure password
        password = request.form.get("password")
        # at least one letter, one number, one special character, total length of at least 8
        if not re.match(
            r"(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$", password
        ):
            return apology("insecure password")

        try:
            id = db.execute(
                "INSERT INTO users (username, hash) VALUES(?, ?)",
                request.form.get("username"),
                generate_password_hash(request.form.get("password")),
            )
        except ValueError:
            return apology("username already exists")

        # login
        session["user_id"] = id

        flash("Registered!")
        return redirect("/")

    else:
        return render_template("register.html")
