def hexadecimal_vers_binaire(hexadecimal):
    valeur = hexadecimal.replace(" ", "").zfill(16)
    return ''.join(format(int(ch, 16), '04b') for ch in valeur)

def xor_binaire(a, b):
    return ''.join('1' if x != y else '0' for x, y in zip(a, b))

def decaler(sequence, nombre):
    return sequence[nombre:] + sequence[:nombre]

def binaire_vers_hexadecimal(binaire):
    return hex(int(binaire, 2))[2:].zfill(16)

def appliquer_permutation(binaire, table):
    return ''.join(binaire[i - 1] for i in table)
