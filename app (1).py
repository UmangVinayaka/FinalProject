import os
import datetime
import re

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# transactions table
db.execute(
    "CREATE TABLE IF NOT EXISTS transactions (id INTEGER PRIMARY KEY, symbol TEXT, name TEXT, shares INTEGER, user_id INTEGER, price REAL, time TIMESTAMP, FOREIGN KEY(user_id) REFERENCES users(id))"
)


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


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "POST":
        symbol = request.form.get("symbol")
        looked_up_symbol = lookup(symbol)
        if not symbol:
            return apology("stock symbol must be provided")
        if looked_up_symbol == None:
            return apology("stock does not exist")

        shares = request.form.get("shares")
        if not shares:
            return apology("shares must be provided")
        try:
            shares = int(shares)
        except ValueError:
            return apology("shares must be an integer")
        if shares <= 0:
            return apology("shares must positive")

        price = looked_up_symbol["price"]
        name = looked_up_symbol["name"]

        user = db.execute(
            "SELECT cash FROM users WHERE id = :user_id", user_id=session["user_id"]
        )
        cash_balance = user[0]["cash"]

        shares_cost = price * shares
        if shares_cost > cash_balance:
            return apology("not enough in balance to buy")
        else:
            cash_balance -= shares_cost
            db.execute(
                "UPDATE users SET cash = :cash_balance WHERE id = :user_id",
                cash_balance=cash_balance,
                user_id=session["user_id"],
            )
            db.execute(
                "INSERT INTO transactions (symbol, name, shares, user_id, price, time) VALUES(?, ?, ?, ?, ?, ?)",
                symbol,
                name,
                shares,
                session["user_id"],
                price,
                datetime.datetime.now(),
            )
            flash("Bought!")
            return redirect("/")

    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    history = db.execute("SELECT symbol, shares, price, time FROM transactions")
    return render_template("history.html", history=history)


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


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("stock symbol invalid")

        shares_owned = db.execute(
            "SELECT SUM(shares) as total_shares FROM transactions WHERE symbol = :symbol",
            symbol=symbol,
        )
        total_shares = shares_owned[0]["total_shares"]

        shares = request.form.get("shares")
        if not shares:
            return apology("shares must be provided")
        try:
            shares = int(shares)
        except ValueError:
            return apology("shares must be an integer")
        if shares <= 0:
            return apology("shares must positive")
        if shares > total_shares:
            return apology("not enough shares owned")

        looked_up_stock = lookup(symbol)
        price = looked_up_stock["price"]
        name = looked_up_stock["name"]

        # update transactions table
        db.execute(
            "INSERT INTO transactions (symbol, name, shares, user_id, price, time) VALUES(?, ?, ?, ?, ?, ?)",
            symbol,
            name,
            (-1 * shares),
            session["user_id"],
            price,
            datetime.datetime.now(),
        )

        # add profit from stock sale to current cash holdings
        additional_cash = price * shares
        db.execute(
            "UPDATE users SET cash = cash + :additional_cash WHERE id = :user_id",
            additional_cash=additional_cash,
            user_id=session["user_id"],
        )

        flash("Sold!")
        return redirect("/")

    else:
        unique_stocks = db.execute(
            "SELECT symbol FROM transactions WHERE user_id = :user_id GROUP BY symbol HAVING SUM(shares) > 0",
            user_id=session["user_id"],
        )

        return render_template("sell.html", unique_stocks=unique_stocks)
