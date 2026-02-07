import asyncio, sys, time

import jwt

sys.path.append(__file__.rsplit("/", 2)[0])
import webtoken


def benchmark(iterations=100):

    payload = {
        "sub": "user_1234567890",
        "name": "Alice Smith",
        "email": "alice.smith@example.com",
        "roles": ["admin", "editor", "viewer"],
        "permissions": ["read:users", "write:users", "delete:users"],
        "metadata": {"login_count": 42, "last_ip": "127.0.0.1"},
        "exp": int(time.time()) + 3600
    }

    def run_bench(label, func, iterations=iterations):
        
        if func is None:
            print(f"{label:<25}: {'N/A':>10}")
            return None
        
        # Warmup
        try:
            func()
        except Exception as e:
            print(f"{label:<25}: FAILED ({e})")
            return None

        start = time.time()
        for _ in range(iterations):
            func()
        end = time.time()
        avg = (end - start) / iterations * 1_000_000 # microseconds
        print(f"{label:<25}: {avg:8.2f} µs/op")
        return avg


    def compare_algo(alg_name, comp_iterations=None, is_symmetric=False):

        comp_iterations = comp_iterations or iterations
        print(f"\n[ {alg_name} ]")
        
        # Keys
        if is_symmetric:
            priv, pub = "secret", "secret"
        else:
            priv_bytes, pub_bytes = webtoken.generate_key_pair(alg_name)
            # PyJWT prefers strings
            priv, pub = priv_bytes.decode('utf-8'), pub_bytes.decode('utf-8')

        # Encode
        webtoken_enc_func = lambda: webtoken.encode(payload, priv, algorithm=alg_name)
        has_pyjwt = alg_name not in ["ML-DSA-65", "ES256K", "ML-DSA-44", "ML-DSA-87"]
        pyjwt_enc_func = (lambda: jwt.encode(payload, priv, algorithm=alg_name)) if has_pyjwt else None
        
        t_enc = run_bench("Toke Encode", webtoken_enc_func)
        p_enc = run_bench("PyJWT Encode", pyjwt_enc_func)

        # Decode
        token = webtoken.encode(payload, priv, algorithm=alg_name)
        webtoken_dec_func = lambda: webtoken.decode(token, pub, algorithms=[alg_name])
        pyjwt_dec_func = (lambda: jwt.decode(token, pub, algorithms=[alg_name])) if has_pyjwt else None
        
        t_dec = run_bench("Toke Decode", webtoken_dec_func, )
        p_dec = run_bench("PyJWT Decode", pyjwt_dec_func, )

        res = []
        if t_enc and p_enc: res.append(f"Enc: {p_enc/t_enc:.1f}x")
        if t_dec and p_dec: res.append(f"Dec: {p_dec/t_dec:.1f}x")
        if res:
            print(f" >>> Speedup: {' | '.join(res)}")

    print(f"--- Benchmarking ({iterations} iterations) ---")
    
    # Standard
    compare_algo("HS256", is_symmetric=True)
    compare_algo("RS256")
    compare_algo("ES256")
    compare_algo("EdDSA") # PyJWT supports this if cryptography >= 2.6
    
    # Heavy
    compare_algo("ES512") # NIST P-521
    
    # Toke Exclusives
    compare_algo("ES256K") # secp256k1
    compare_algo("ML-DSA-65") # Post-Quantum


if __name__ == "__main__":

    benchmarks = (benchmark,
        )

    for benchmark in benchmarks:
        benchmark()
        pass

    # asyncio.run(async_benchmark())
