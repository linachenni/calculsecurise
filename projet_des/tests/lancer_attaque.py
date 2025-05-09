from attaque.sous_cle_k16 import extraire_k16
from attaque.reconstitution_k import remonter_cle

message_clair = "75 8C C1 02 52 FB EA B9"

message_chiffre_valide = "4A 17 74 38 D8 F1 BE DB"

messages_faux = [
    "0A 07 66 78 90 A5 BE DB",
    "5B 57 31 18 CC F3 AE 9B",
    "42 17 F0 28 89 E1 BE DB",
    "0A 05 74 30 D8 A4 BE DB",
    "42 17 60 38 88 A1 B6 DB",
    "0A 37 74 38 D8 F1 AF D2",
    "5A 17 75 38 F8 F1 8E 9B",
    "5E 13 34 28 D9 71 BE EB",
    "4B 47 F4 6C CB F0 BE DB",
    "0A 13 74 30 D8 25 BE CB",
    "48 12 54 7C D8 F1 AE 9F",
    "4B C7 70 3E C9 F0 FA DB",
    "49 12 74 7C C8 F1 BC DF",
    "4A 5F 70 39 98 F5 BE D9",
    "0A 17 74 38 90 E5 B6 DB",
    "1E 17 75 38 DC D1 BE 92",
    "4A 16 54 28 59 F1 EE 9F",
    "5F 47 71 3E C8 D0 BE DB",
    "DA 17 7D 38 98 E5 FA DB",
    "4A 36 74 B8 DD F1 AB 8F",
    "DA 12 75 38 D8 F1 7A DF",
    "4A 10 74 78 D8 F0 BE 4B",
    "4A 47 74 7C DA F0 BC DB",
    "0A 57 70 38 98 AD BE D9",
    "4E 17 7D 38 B8 E5 AE 9B",
    "0A 16 74 B8 D9 B9 BA CF",
    "6A 07 76 78 DC B1 AF DA",
    "5A 1F 35 19 9C E1 AE 9B",
    "6A 17 35 38 DC B1 8F DA",
    "5E 97 34 28 D8 F1 FA FB",
    "4A 16 74 28 59 F1 7E CB",
    "4B 42 70 38 C8 F2 BE 4B"
]

if __name__ == "__main__":
    k16 = extraire_k16(message_chiffre_valide, messages_faux)
    print(f"Sous-clé K16: {k16}")

    cle_complete = remonter_cle(k16, message_clair, message_chiffre_valide)
    if cle_complete:
        print(f"Clé complete K: {cle_complete}")
    else:
        print("Echec de la reconstitution de la clé")
