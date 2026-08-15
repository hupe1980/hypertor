"""Hosting an onion service.

    python python_examples/onion_service.py
"""

import hypertor

# `state_dir` is what keeps the .onion address stable across restarts: the
# address is derived from a key stored there. Without it, every start produces
# a brand-new address.
app = hypertor.OnionApp("my-service", state_dir="./onion-state")


@app.get("/")
def home(request):
    return "<h1>Hello from a .onion service</h1>"


@app.get("/health")
def health(request):
    return {"status": "ok"}


@app.get("/users/{user_id}")
def get_user(request):
    return {"id": request.params["user_id"]}


@app.post("/echo")
def echo(request):
    return {"received": request.json()}


if __name__ == "__main__":
    # Prints the .onion address, then serves until interrupted.
    app.run()
