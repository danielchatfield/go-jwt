## go-jwt

This is an implementation of JSON Web tokens written in go.

# Limitations

This library completely ignores the `alg` field in the header. You are required
to know which algorithm and key was used, doing anything else has security
implications.
