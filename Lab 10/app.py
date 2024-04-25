from flask import Flask
app = Flask(__name__)

if __name__ == "__main__":
    app.run(ssl_context=('C:/Users/krish/Desktop/6th-Sem/Network-Security-CSE-315L/Lab 10/domain.crt', 'C:/Users/krish/Desktop/6th-Sem/Network-Security-CSE-315L/Lab 10/domain.key'))
