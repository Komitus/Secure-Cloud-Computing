from schemas import create_app
from waitress import serve


HOST = "0.0.0.0"
PORT = 8443
PATH ="/etc/letsencrypt/live/knowak.thenflash.com"
DEBUG = True

def main():
    app = create_app()
    app.run(host=HOST, port=PORT, ssl_context=(f'{PATH}/fullchain.pem', f'{PATH}/privkey.pem'), debug=DEBUG)

if __name__ == "__main__":
    main()