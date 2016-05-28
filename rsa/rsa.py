import math
import random
import sys

# teste de primalidade de Fermat
def fermat(p, tests=20):
    if p & 1 == 0:
        return False
    for _ in range(tests):
        if pow(random.randrange(2, p-1), p-1, p) != 1:
            return False
    return True

# algoritmo de Euclides extendido e adaptado
def inv_mul(a, b):
    x, y, newx, newy = 0, b, 1, a
    while newy:
        q = y // newy  # quociente
        x, y, newx, newy = newx, newy, x - q*newx, y - q*newy
    assert(x <= 1)  # se x > 1, a nao tem inversa multiplicativa
    return x % b

# gera um primo aleatorio no intervalo [lower, upper)
def random_prime(lower, upper):
    while True:
        p = random.randrange(lower, upper)
        if fermat(p):
            return p


class KeyPair:
    def __init__(self, b):
        # o tamanho da chave precisa ser potencia de 2 e positivo
        assert(b & (b-1) == 0 and b > 0)

        # tamanho em bits de p e q para que n tenha b bits
        l = b // 2

        # p e q nao sao necessarios apos gerar n e phi, mas sao
        # guardados para fins didaticos
        p = self.p = random_prime(2 ** (l-1), 2 ** l)
        q = self.q = random_prime(2 ** (l-1), 2 ** l)
        self.n = p * q

        # e pode ser qualquer primo, 65537 eh rapido e razoavel
        self.e = 65537

        # encontrar inversa multiplicativa pelo algoritmo de Euclides
        self.d = inv_mul(self.e, self.n - (p+q-1))
        assert((self.d * self.e) % (self.n - (p+1-1)) == 1)

    def public_key(self):
        return self.n, self.e

    def private_key(self):
        return self.d

# cria um par de chaves de tamanho indicado pelo primeiro argumento
kp = KeyPair(int(sys.argv[1]))
print('p = {}\nq = {}\nn = {}'.format(kp.p, kp.q, kp.n))
print('public key = {}'.format(kp.public_key()))
print('private key = {}'.format(kp.private_key()))
