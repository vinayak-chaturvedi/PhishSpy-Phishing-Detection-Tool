
from flask import Flask, request, json
from main import main
from flask_cors import CORS, cross_origin
import sqlite3

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

@app.route('/checkphishing', methods=["POST"])
@cross_origin(origin='*')
def checkphishing():
    content_type = request.headers.get('Content-Type')
    if (content_type == 'application/json'):
        json = request.get_json()
        if "url" not in json.keys():
            return {"message" : "parameter missing"}
        url = json["url"]
        try:
            response = main(url)
            return response
        except:
            return {"status-code" : -1, "message" : "Internal Error, admin is notified"}
    else:
        return "Content-Type not supported!"

@app.route('/count')
@cross_origin(origin='*')
def checkcount():
    conn = sqlite3.connect("database.db")
    cur = conn.cursor()
    cur.execute("select count from phishcount where key=1")
    curr_count = cur.fetchall()[0][0]
    conn.close()
    return {"status" : 200, "count": curr_count}

@app.route('/')
@cross_origin(origin='*')
def home():
    return {"status" : 200, "message": "Welcome to PhishSpy API"}






if __name__ == '__main__':

	app.run(host='0.0.0.0', port=8000, debug=True)
