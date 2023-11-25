from schemas import create_app


HOST = "0.0.0.0"
DEBUG = True

def main():
    app = create_app()
    app = app.run(host=HOST, port=8080, debug=DEBUG)
    # app.run(host=HOST, port=PORT, debug=DEBUG)

if __name__ == "__main__":
    main()