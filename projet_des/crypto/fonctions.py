# fonction f du DES
from crypto.permutation import TABLE_EXPANSION, PERMUTATION_FINALE
from outils.operations import appliquer_permutation, xor_binaire
from crypto.boites_s import sortie_boite_s

def fonction_f(entree_droite, sous_cle):
    etendue = appliquer_permutation(entree_droite, TABLE_EXPANSION)
    resultat_xor = xor_binaire(etendue, sous_cle)

    sortie_s = ""
    for i in range(8):
        segment = resultat_xor[i*6:(i+1)*6]
        sortie_s += sortie_boite_s(segment, i)

    sortie_f = appliquer_permutation(sortie_s, PERMUTATION_FINALE)
    return sortie_f
