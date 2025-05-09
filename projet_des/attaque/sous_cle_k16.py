from crypto.permutation import PERMUTATION_INITIALE, PERMUTATION_FINALE, TABLE_EXPANSION
from crypto.boites_s import BOITES_S, sortie_boite_s
from outils.operations import hexadecimal_vers_binaire, appliquer_permutation, xor_binaire

def extraire_k16(correction_hex, fautifs_hex):
    # conversion et permutation initiale du message chiffré juste
    binaire_correct = appliquer_permutation(hexadecimal_vers_binaire(correction_hex), PERMUTATION_INITIALE)
    gauche_ref, droite_ref = binaire_correct[:32], binaire_correct[32:]

    # conversion des messages faux
    binaires_faux = [appliquer_permutation(hexadecimal_vers_binaire(msg), PERMUTATION_INITIALE) for msg in fautifs_hex]
    g_faux = [bf[:32] for bf in binaires_faux]
    d_faux = [bf[32:] for bf in binaires_faux]

    xor_g = [xor_binaire(gauche_ref, g) for g in g_faux]
    xor_d = [xor_binaire(droite_ref, d) for d in d_faux]

    e_droite_ref = appliquer_permutation(droite_ref, TABLE_EXPANSION)
    e_d_faux = [appliquer_permutation(d, TABLE_EXPANSION) for d in d_faux]

    def inverse_permutation_finale(valeur):
        tmp = [''] * 32
        for idx, p in enumerate(PERMUTATION_FINALE):
            tmp[p - 1] = valeur[idx]
        return ''.join(tmp)

    # déduction des morceaux de K16 par S-box
    k16_possible = [[] for _ in range(8)]
    cle_k16 = ''

    for sbox_id in range(8):
        resultats = []
        for i in range(len(fautifs_hex)):
            diff_sbox = inverse_permutation_finale(xor_g[i])[sbox_id*4:(sbox_id+1)*4]
            e_segment_ref = e_droite_ref[sbox_id*6:(sbox_id+1)*6]
            e_segment_faux = e_d_faux[i][sbox_id*6:(sbox_id+1)*6]

            for essai in range(64):
                k_test = format(essai, '06b')
                s_input_ref = xor_binaire(e_segment_ref, k_test)
                s_input_faux = xor_binaire(e_segment_faux, k_test)

                s_ref = sortie_boite_s(s_input_ref, sbox_id)
                s_faux = sortie_boite_s(s_input_faux, sbox_id)
                if xor_binaire(s_ref, s_faux) == diff_sbox:
                    resultats.append(k_test)

        # on sélectionne le k_test commun à ttes les itérations
        from collections import Counter
        plus_frequent = Counter(resultats).most_common(1)[0][0]
        cle_k16 += plus_frequent

    return cle_k16
