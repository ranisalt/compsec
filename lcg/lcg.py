class LinearCongruentialGenerator:
    mul = 1103515245  # a, 0 < a < m
    inc = 12345       # c, 0 <= c < m
    mod = 2 ** 31     # m, 0 < m

    def __init__(self, seed):
        self.seed_ = seed % self.mod  # X[0], 0 <= X[0] < m

    def rand(self):
        # X[n + 1] = (a * X[n] + c) mod m
        self.seed_ = (self.seed_ * self.mul + self.inc) % self.mod
        return self.seed_
