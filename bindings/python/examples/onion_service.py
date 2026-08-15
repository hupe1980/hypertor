"""Hosting an onion service.

python examples/onion_service.py
"""

import hypertor

# The nickname is the identity: the .onion address is derived from a key filed
# under it, and arti's default state directory is persistent. Relaunching with
# the same nickname republishes the *same* address, with or without state_dir —
# that argument only chooses where the key lives.
app = hypertor.OnionApp("my-service", state_dir="./onion-state")

_USERS = {"1": {"id": "1", "name": "Alice"}}


@app.get("/")
def home(request):
    return "<h1>Hello from a .onion service</h1>"


@app.get("/health")
def health(request):
    return {"status": "ok"}


@app.get("/users/{user_id}")
def get_user(request):
    user = _USERS.get(request.params["user_id"])
    if user is None:
        # Flask's convention: (body, status) and (body, status, headers).
        return {"error": "no such user"}, 404
    return user


@app.post("/users")
def create_user(request):
    user = request.json()
    _USERS[user["id"]] = user
    return user, 201, {"location": f"/users/{user['id']}"}


@app.post("/echo")
def echo(request):
    return {"received": request.json()}


if __name__ == "__main__":
    # Prints the .onion address, then serves until Ctrl-C.
    app.run()
