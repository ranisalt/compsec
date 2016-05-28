from functools import lru_cache, reduce
from math import ceil, gcd, sqrt
from typing import List


@lru_cache(maxsize=None)
def prime(n: int) -> bool:
    # retorna true se todos os numeros em [2, sqrt(n)] nao dividem n
    return all(n%i != 0 for i in range(2, ceil(sqrt(n))+1))


# gerador de fatores primos de n
def prime_factors(n: int) -> int:
    # se n for par, gera 2
    if n&1 == 0:
        yield 2

    # gera p para cada p primo em [3, sqrt(n)] que divide n
    for p in range(3, n//2 + 1, 2):
        if prime(p) and n%p == 0:
            yield p

    # gera n se n for primo
    if prime(n):
        yield n


def phi(n: int) -> int:
    # soma 1 para cada i relativamente primo de n
    return sum(gcd(i, n) == 1 for i in range(1, n))


def primitive_roots(n: int) -> List[int]:
    phi_n = phi(n)

    output = []
    # testa para todos os valores de a (2 ate n-1)
    for a in range(2, n):
        # para m ser raiz primitiva de n devem ser relativamente primos
        if gcd(a, n) != 1 or not prime(n):
            continue

        # verifica a^(phi(n) / p) mod n para cada fator primo p de phi(n)
        if all(pow(a, phi_n//p, n) != 1 for p in prime_factors(phi_n)):
            output.append(a)

    return output


def main():
    for n in range(2, 2000):
        roots_str = ', '.join(str(i) for i in primitive_roots(n))
        if len(roots_str) > 0:
            print('prts mod {0}: {1}'.format(n, roots_str))


main()
