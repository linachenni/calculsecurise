# chiffrement du message avec le DES
from outils.operations import hexadecimal_vers_binaire, binaire_vers_hexadecimal, xor_binaire, appliquer_permutation
from crypto.permutation import PERMUTATION_INITIALE, PERMUTATION_INVERSE
from crypto.cles import generer_sous_cles
from crypto.fonctions import fonction_f

def des_chiffrer(message_hexa, cle_hexa):
    message_bin = hexadecimal_vers_binaire(message_hexa)
    cle_bin = hexadecimal_vers_binaire(cle_hexa)
    sous_cles = generer_sous_cles(cle_bin)

    permute = appliquer_permutation(message_bin, PERMUTATION_INITIALE)
    g, d = permute[:32], permute[32:]

    for i in range(16):
        g, d = d, xor_binaire(g, fonction_f(d, sous_cles[i]))

    inverse = appliquer_permutation(d + g, PERMUTATION_INVERSE)
    return binaire_vers_hexadecimal(inverse)
