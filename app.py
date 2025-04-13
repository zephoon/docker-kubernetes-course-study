from flask import Flask

app = Flask(__name__)

@app.route("/api/v1/hello")
def hello_world():
    return {'demo': '"Hello, World!'}