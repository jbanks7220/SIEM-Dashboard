from flask import Flask, render_template, jsonify
import json

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/logs')
def get_logs():
    with open('static/data/logs.json') as f:
        logs = json.load(f)
    return jsonify(logs)

if __name__ == '__main__':
    app.run(debug=True)
