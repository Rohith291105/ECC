# ECC Lab

Elliptic-curve cryptography from scratch, with a Python backend and a browser frontend.
Educational only: not constant-time, not for production.

## Run
    python server.py          # needs Python 3.8+, no dependencies
    # open http://127.0.0.1:8000
    python -m unittest -v     # run the test suite

## Layout
- `ecc.py`        field/point arithmetic, double-and-add, ECDH, ECDSA (curves: toy17, secp256k1)
- `server.py`     JSON API + static file server (standard library)
- `static/index.html`  UI: curve plot, point ops, key pairs, ECDH demo, sign/verify
- `test_ecc.py`   known vectors, group-law properties, invalid input, nonce-reuse attack

## API (all POST JSON except GET /api/curves, /api/points?curve=toy17)
`/api/keygen {curve}` · `/api/add {curve,P,Q}` · `/api/mul {curve,k,P}` · `/api/oncurve {curve,P}`
`/api/ecdh {curve,priv,pub}` · `/api/sign {curve,priv,msg}` · `/api/verify {curve,pub,msg,sig:{r,s}}`
Points: `{"x":"5","y":"1"}` or `{"inf":true}`; numbers are strings (decimal or 0x hex).

## Ideas to extend
Wycheproof/NIST vectors, RFC 6979 deterministic nonces, Jacobian coordinates, Ed25519/P-256,
Flask/FastAPI port, API tests with pytest, Selenium/Playwright UI tests.
