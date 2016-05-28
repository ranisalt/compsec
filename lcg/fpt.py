def fermat(p, tests=20):
    for i in range(tests):
        # assuma generator sendo um gerador de numeros qualquer
        # modulo e soma necessarios para que 0 < a < p
        a = (generator.rand() % (p - 1)) + 1

        # algoritmo de exp. modular, aka a^(p - 1) mod p
        if pow(a, p - 1, p) != 1:
            return False

    return True
