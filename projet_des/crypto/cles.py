# génération des sous clés à partir d'une clé principale de 64 bits
from outils.operations import appliquer_permutation, decaler
from crypto.permutation import PC1, PC2, TOURS_ROTATION

def generer_sous_cles(cle64):
    cle56 = appliquer_permutation(cle64, PC1)
    gauche, droite = cle56[:28], cle56[28:]
    sous_cles = []

    for rotation in TOURS_ROTATION:
        gauche = decaler(gauche, rotation)
        droite = decaler(droite, rotation)
        sous_cles.append(appliquer_permutation(gauche + droite, PC2))

    return sous_cles
