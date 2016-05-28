import functools
import math
import random


digits = 10


class Partner:
    def __init__(self, p, g):
        self.p = p
        self.g = g
        self.secret = random.randint(1, p)

    def first_step(self):
        return pow(self.g, self.secret, self.p)

    def second_step(self, other):
        self.s = pow(other, self.secret, self.p)


@functools.lru_cache(maxsize=None)
def prime(p, tests=20):
    for _ in range(min(p, tests)):
        a = random.randrange(2, p)
        if pow(a, p - 1, p) != 1:
            return False
    return True


def prime_factors(n):
    if n & 1 == 0:
        yield 2

    for p in range(3, int(math.sqrt(n)) + 1, 2):
        if prime(p) and n % p == 0:
            yield p

    if prime(n):
        yield n


@functools.lru_cache(maxsize=None)
def phi(n):
    # passo base
    if n < 2:
        return 0

    # se n é primo, ele é relativamente primo a todos antes dele
    if prime(n):
        return n - 1

    # igual ao if abaixo, apenas evitando testar para os pares também
    if (n & 1) == 0:
        m = n >> 1
        return phi(m) << 1 if not (m & 1) else phi(m)

    # testar para todos os primos menores que n
    for p in range(3, n, 2):
        if prime(p):
            if n % p:
                continue

            # phi é multiplicativo, se p divide n (p*o = n) é possível utilizar
            # p (que é menor que n) para calcular o phi de n
            o = n // p
            d = math.gcd(p, o)
            partial = phi(p) * phi(o)
            return partial if d == 1 else partial * d / phi(d)


def primitive_root(n):
    phi_n = phi(n)
    factors = prime_factors(phi_n)

    for a in range(3, n):
        if math.gcd(a, n) != 1:
            continue

        if all(pow(a, phi_n // next(factors), n) != 1 for _ in range(5)):
            return a


g = None
while g is None:
    p = random.randrange(10 ** (digits - 1) + 1, 10 ** digits + 1, 2)
    if prime(p):
        g = primitive_root(p)

print('p = {}, g = {}'.format(p, g))

alice = Partner(p, g)
bob = Partner(p, g)
bob.second_step(alice.first_step())
alice.second_step(bob.first_step())

print('As = {}, Bs = {}'.format(alice.s, bob.s))
