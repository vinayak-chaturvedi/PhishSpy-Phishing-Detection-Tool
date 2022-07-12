from functions import run
import sqlite3
import validators
from validators import ValidationFailure
import urllib.request

def is_string_an_url(url_string: str) -> bool:
    result = validators.url(url_string)

    if isinstance(result, ValidationFailure):
        return False

    return result

def website_is_up(url):
    try:
        status_code = urllib.request.urlopen(url).getcode()
        return status_code == 200
    except:
        return False
    

def main(url):
    response = {}

    conn = sqlite3.connect("database.db")
    cur = conn.cursor()
    cur.execute("select count from phishcount where key=1")
    curr_count = cur.fetchall()[0][0]
    cur.execute("select count from phishcount where key=1")
    cur.execute(f"update phishcount set count = {curr_count + 1} where key = 1")
    conn.commit()
    conn.close()

    if(not is_string_an_url(url)):
        response["status-code"] = 11
        response["message"] = "Invalid URL Entered"
        return response
    if(website_is_up(url) == False):
        response["status-code"] = 12
        response["message"] = "URL is down or currently unavailable"
        return response
    
    suspectScore, summary = run(url)
    phish_percent = round((suspectScore/82)*100,2)

    response["status-code"] = 10
    response["phish_percent"] = phish_percent
    response["summary"] = summary
    return response


    




