import sqlite3 as sql
import time
import random
import bcrypt
import threading

#The counter was read and written in seperate files operations with a time gap in between 
#Two logins at the same time will cause a lost update
#FIX = Thread lock for the visitor counter
counter_lock = threading.Lock() 


def insertUser(username, password, DoB):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    # Passwords were stored in plain text meaning anyone who accessed the database could read every password immediately
    # FIX = Hash password with bcrypt before storing
    # bcrypt applies a one way hash so even if the database is exposed passwords cannot be read directly
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    cur.execute(
        "INSERT INTO users (username,password,dateOfBirth) VALUES (?,?,?)",
        (username, hashed_password, DoB),
    ) 
    con.commit()
    con.close()


def retrieveUsers(username, password):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    # inserted the username directly into the qurey, which means an attacker could type ' or '1'='1' into the login field and bypass authetication completly without needing a real password.
    # FIX = Parameterise query replaces f-string concatenation. 
    # the ? placeholder passes the username as a seperate data value so no matter what it contains it can never alter the query.
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    if cur.fetchone() == None:
        con.close()
        return False
    else:
        # Same SQL injection vulnerability exists here on the password feild aswell
        #FIX = Parameterise query replaces f-string concatenation
        cur.execute("SELECT * FROM users WHERE password = ?", (password,))
        # Plain text log of visitor count as requested by Unsecure PWA management

        #FIX=Lock prevents simultaneous access
        #Sleep removed 
        with counter_lock:
            with open("visitor_log.txt", "r") as file:
                number = int(file.read().strip())
                number += 1
            with open("visitor_log.txt", "w") as file:
                file.write(str(number))
        #The stored password is a bcrypt hash. checkpw hashes the submitted password and compare it
        #FIX = Verify password using bcrypt instead of plain text comparison
        #Plain text is never stored or compared
        user_row = cur.fetchone()
        if user_row is None:
            con.close()
            return False
        stored_hash = user_row[2]
        if not bcrypt.checkpw(password.encode('utf-8'), stored_hash):
            con.close()
            return False
        else:
            con.close()
            return True


def insertFeedback(feedback):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    #An attacker could submit feedback containing a SQL such as '); DROP TABLE feedback; -- which would run againt the database and destroy all stored data. 
    # The ? placeholder treats the entire feedback string as a plain data regardless of what SQL characters it contains
    cur.execute("INSERT INTO feedback (feedback) VALUES (?)", (feedback,))
    con.commit()
    con.close()


def listFeedback():
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    data = cur.execute("SELECT * FROM feedback").fetchall()
    con.close()
    f = open("templates/partials/success_feedback.html", "w")
    for row in data:
        f.write("<p>\n")
        f.write(f"{row[1]}\n")
        f.write("</p>\n")
    f.close()
