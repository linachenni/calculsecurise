from outils.operations import appliquer_permutation, hexadecimal_vers_binaire
from crypto.permutation import PC2, PC1
from crypto.chiffrement import des_chiffrer

def remonter_cle(k16_binaire, clair_hex, attendu_hex):
    partiel = ['2'] * 56
    for idx, pos in enumerate(PC2):
        partiel[pos - 1] = k16_binaire[idx]

    from itertools import product
    cas_possibles = []
    for bits in product("01", repeat=partiel.count('2')):
        tentative = partiel[:]
        bit_iter = iter(bits)
        for i in range(56):
            if tentative[i] == '2':
                tentative[i] = next(bit_iter)
        cas_possibles.append(''.join(tentative))

    def vers_64_bits(cle_56):
        tmp = ['2'] * 64
        for i, pos in enumerate(PC1):
            tmp[pos - 1] = cle_56[i]
        return tmp

    # complète les bits 2 par parité simple
    cles_64_finales = []
    for c56 in cas_possibles:
        brute = vers_64_bits(c56)
        for i in range(8):
            bloc = brute[i*8:(i+1)*8]
            bloc = ['0' if bloc[j] == '2' else bloc[j] for j in range(8)]
            # pour chaque bloc de 7 bits on ajt un bit pour obtenir un nombre impair de 1
            parite = '1' if bloc[:7].count('1') % 2 == 0 else '0'
            bloc[7] = parite
            brute[i*8:(i+1)*8] = bloc
        cles_64_finales.append(''.join(brute))

    # test chaque clé potentielle
    clair_binaire = hexadecimal_vers_binaire(clair_hex)
    for cle in cles_64_finales:
        sortie = des_chiffrer(clair_hex, hex(int(cle, 2))[2:].zfill(16))
        if sortie.lower() == attendu_hex.replace(" ", "").lower():
            return hex(int(cle, 2))[2:].zfill(16)
    return None
