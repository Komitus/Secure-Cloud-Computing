from schemas import create_app
from waitress import serve


HOST = "0.0.0.0"
PORT = 8080

def main():
    app = create_app()
    app.run(host=HOST, port=PORT)

if __name__ == "__main__":
    main()