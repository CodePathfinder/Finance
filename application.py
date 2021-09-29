import os

from datetime import datetime
from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash


from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


# Make sure API_TOKEN is set
if not os.environ.get("API_TOKEN"):
    raise RuntimeError("API_TOKEN not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    data = []
    shares_value = 0

    # extract data (symbol and number of shares) from state table for active user
    user_shares = db.execute(
        "SELECT symbol, shares FROM state WHERE user_id=?", session["user_id"])

    for share in user_shares:
        symbol = share.get('symbol')
        shares = share.get('shares')

        # call lookup() function and get market price of the share
        quoted = lookup(symbol)
        name = quoted.get('name')
        price = quoted.get('price')

        # incorporation of the share's data in tuple
        share_data = (symbol, name, shares, usd(price), usd(shares * price))

        # append data as list of tuples
        data.append(share_data)

        # calculate total value of all user's shares
        shares_value += (shares * price)

    cash_data = db.execute(
        "SELECT cash FROM users WHERE id=?", session["user_id"])

    cash = cash_data[0].get('cash')

    grand_total = shares_value + cash

    return render_template("index.html", data=data, cash=usd(cash), grand_total=usd(grand_total))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "POST":

        if not request.form.get("symbol"):
            return apology("please provide share's symbol")

        else:
            # Obtain data from IEX, including the current price of the shares - dictionary
            quoted = lookup(request.form.get("symbol"))

            # verification of the user's symbol submit
            if not quoted:
                return apology("please check the share's 'symbol'")

        # verify the user's shares submit

        if not request.form.get("shares") or not request.form.get("shares").isdigit() or int(request.form.get("shares")) <= 0:
            return apology("please enter number of shares as positive integer")

        else:
            # extract values from 'quoted' dictionary, getting up the keys
            price = quoted.get('price')
            symbol = quoted.get('symbol')

            session_user_id = session["user_id"]

            # extract from 'users' table information on available cash; format: list of dictionaries
            available_cash_data = db.execute(
                "SELECT cash FROM users WHERE id=:session_user_id", session_user_id=session_user_id)

            # extract available cash value from dictionary, with getting up the key('cash')
            available_cash = available_cash_data[0].get('cash')

            shares = int(request.form.get("shares"))

        # Render apology, if user cannot afford the shares at the current price
        if available_cash < (price * shares):
            return apology("not enough cash on your account")

        # Transaction is valid, update data (user's cash, user's shares, transaction history) in database tables 'users', 'state', 'transactions'
        else:
            available_cash = available_cash - (price * shares)
            db.execute("UPDATE users SET cash=? WHERE id=?",
                       available_cash, session_user_id)
            db.execute("INSERT INTO transactions (user_id, symbol, transaction_type, transaction_price, shares, transaction_time) VALUES (?, ?, ?, ?, ?, ?)",
                       session_user_id, symbol, 'buy', price, shares, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

            # shares quantity data are extracted from state table in the form of list of dictionaries
            shares_quantity_data = db.execute(
                "SELECT shares FROM state WHERE user_id=? AND symbol=?", session_user_id, symbol)

            # if user buys the shares for the first time (no shares in state table), add the row in state table adding the shares data
            if not shares_quantity_data:
                db.execute("INSERT INTO state (user_id, symbol, shares) VALUES (?, ?, ?)",
                           session_user_id, symbol, shares)

            # otherwise update number of shares in the state table
            else:
                # extract shares quantity value from the list of dictionary 'shares_quantity_data', with getting up the key('shares')
                shares_quantity = shares_quantity_data[0].get('shares')
                update_shares = shares_quantity + shares
                db.execute("UPDATE state SET shares=? WHERE user_id=? AND symbol=?",
                           update_shares, session_user_id, symbol)

        return redirect("/")
    else:

        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    data = db.execute("SELECT * FROM transactions WHERE user_id=:session_user_id",
                      session_user_id=session["user_id"])
    for row in data:
        row.pop('user_id')
        if row.get('transaction_type') == 'sell':
            row['shares'] = row['shares']*(-1)
        row['transaction_price'] = usd(row['transaction_price'])
    return render_template("history.html", data=data)


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
            return apology("enter your password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password, if you are not registered, please register first", 403)

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
    if request.method == "POST":
        quoted = lookup(request.form.get("symbol"))
        if not quoted:
            return apology("No data available, check share's 'symbol'")
        quoted['price'] = usd(quoted['price'])
        return render_template("quoted.html", quoted=quoted)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        names = []

        usnames = db.execute("SELECT username FROM users")
        for usname in usnames:
            names.append(usname['username'])

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure registrant's username is uniq
        elif request.form.get("username") in names:
            return apology("this username already exists, try once again", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("please enter your password", 403)

        # Ensure password is duly confirmed
        elif request.form.get("confirmation") != request.form.get("password"):
            return apology("passwords do not match", 403)

        # Insert new user into users
        db.execute("INSERT INTO users (username, hash) VALUES (:username, :hash)", username=request.form.get("username"),
                   hash=generate_password_hash(request.form.get("password"), method='pbkdf2:sha256', salt_length=8))

        # log in the new user
        new_user_id = db.execute(
            "SELECT id FROM users WHERE username=:username", username=request.form.get("username"))

        session["user_id"] = new_user_id[0].get("id")

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/changepass", methods=["GET", "POST"])
@login_required
def changepass():
    """Change user password"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure valid password is submitted
        if not request.form.get("password"):
            return apology("please enter your valid password")

        # Ensure that old password is correct
        password_data = db.execute(
            "SELECT hash FROM users WHERE id=:session_user_id", session_user_id=session["user_id"])
        if len(password_data) != 1 or not check_password_hash(password_data[0]["hash"], request.form.get("password")):
            return apology("invalid password, try again")

        # Ensure new password is submitted
        if not request.form.get("new password"):
            return apology("please enter your new password")

        # Ensure password is duly confirmed
        elif request.form.get("new password confirmation") != request.form.get("new password"):
            return apology("passwords do not match", 403)

        # Update user's password into users("hash")
        db.execute("UPDATE users SET hash=:hash", hash=generate_password_hash(request.form.get("new password"),
                                                                              method='pbkdf2:sha256', salt_length=8))

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("changepass.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    if request.method == "POST":

        # verify the user's shares sell submit
        sell_symbol = request.form.get("symbol")
        if not sell_symbol:
            return apology("please provide share's symbol")
        sell_shares_str = request.form.get("shares")
        if not sell_shares_str or not sell_shares_str.isdigit():
            return apology("please provide the number of shares as positive integer")
        elif int(sell_shares_str) <= 0:
            return apology("please provide positive integer for number of shares, min: 1")
        sell_shares = int(sell_shares_str)

        # check if user owns the shares of that stock
        shares = db.execute("SELECT symbol, shares FROM state WHERE user_id=:session_user_id and symbol=:symbol",
                            session_user_id=session["user_id"], symbol=request.form.get("symbol"))
        balance_shares = shares[0].get('shares')

        if sell_symbol != shares[0].get('symbol'):
            return apology("no shares of that stock in your portfolio")

        elif sell_shares > balance_shares:
            return apology("not enough shares of that stock in your portfolio")

        else:
            # Obtain data from IEX, including the current price of the shares - dictionary
            quoted = lookup(sell_symbol)

        if not quoted:
            return apology("something went wrong, try again later")

        else:
            # extract values from 'quoted' dictionary, getting up the keys
            price = quoted.get('price')

            # extract from 'users' table information on available cash; format: list of dictionaries
            available_cash_data = db.execute(
                "SELECT cash FROM users WHERE id=:session_user_id", session_user_id=session["user_id"])

            # extract available cash value from dictionary, with getting up the key('cash')
            available_cash = available_cash_data[0].get('cash')

            # update available cash in users
            available_cash = available_cash + (sell_shares * price)
            db.execute("UPDATE users SET cash=:cash WHERE id=:session_user_id", cash=available_cash,
                       session_user_id=session["user_id"])

            # update balance shares in state
            balance_shares = balance_shares - sell_shares
            if balance_shares <= 0:
                db.execute("DELETE FROM state WHERE user_id=:session_user_id AND symbol=:symbol",
                           session_user_id=session["user_id"], symbol=sell_symbol)
            else:
                db.execute("UPDATE state SET shares=? WHERE user_id=? AND symbol=?",
                           balance_shares, session["user_id"], sell_symbol)

            # update history in transcations
            db.execute("INSERT INTO transactions (user_id, symbol, transaction_type, transaction_price, shares, transaction_time) VALUES (?, ?, ?, ?, ?, ?)",
                       session["user_id"], sell_symbol, 'sell', price, sell_shares, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

        return redirect("/")

    else:
        symbols = db.execute(
            "SELECT symbol FROM state WHERE user_id=:session_user_id", session_user_id=session["user_id"])
        return render_template("sell.html", symbols=symbols)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
