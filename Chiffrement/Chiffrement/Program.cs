using System;
using System.Collections.Generic;
using System.Text;

namespace Chiffrement
{
    /*
    ----------------------------------------------------------------------------
    ALGORITHME DE CHIFFREMENT SYMÉTRIQUE BASÉ SUR UNE SUBSTITUTION POLYGRAMMIQUE
    ----------------------------------------------------------------------------

    CHIFFREMENT
    -----------
        - Des PAIRES de lettres sont cryptées, au lieu de lettres UNIQUES comme dans le cas d'un chiffre de substitution simple.
        - Une GRILLE 5 × 5 avec les lettres de l'alphabet sert de clé pour crypter le texte en clair. 
        - Sur les 26 lettres de l'alphabet, on en omet une, généralement 'J'. 
		  Dans ce cas, si le message à chiffrer contient un 'J' alors il sera remplacé par 'I'
        
          Ex :   \	 0  1	2	3	4	
                 ----------------------
                 0 | A	B	C	D	E
                 1 | F	G	H	I	K
                 2 | L	M	N	O   P
                 3 | Q	R	S	T   U
                 4 | V	W	X	Y	Z

        - Cette grille est modifiée en y plaçant les caractères de la clé (on ignore les doublons dans la clé),
  		  puis en la complétant par les caractères absents dans la clé. 
		  Ex : si la clé est "monarchy" (on omet toujours 'J')

                  \	    0   1	2	3	4
                  ----------------------
                  0 |	M	O	N	A	R
                  1 |	C	H	Y	B	D
                  2 |	E	F	G	I   K
                  3 |	L	P	Q	S   T
                  4 |	U	V	W	X	Z

        - Le message à chiffrer est découpé en paires de 2 lettres. 
		  Si le nombre de lettres est impaire, on en ajoute un 'Z'.
          Ex : "instruments" --> 'IN' 'ST' 'RU' 'ME' 'NT' 'SZ'
        
        - Si les 2 lettres apparaissent sur la MÊME COLONNE, les remplacer par celles qui sont juste en dessous
          Ex : pour le couple "ME"  ==> "CL"  (M -> C et E -> L)
                    \   0   
                  --------  
                  0 |	M	
                  1 |	C	* va remplacer 'M'
                  2 |	E	
                  3 |	L	* va remplacer 'E'
                  4 |	U	

        - Si les lettres se trouvent sur la MÊME LIGNE, les remplacer par celles se trouvant immédiatement 
		  à leur droite (en bouclant sur la gauche si le bord de la grille est atteint)
          Ex :   "ST" ==> "TL"  (S -> T et T -> L)  
                    \	 0  1	2	3	4
                    ----------------------
                  3 |	L	P	Q	S   T
					    *				*
       
	   - Si AUCUNE DES RÈGLES ci-dessus n'est vraie: formez un rectangle avec les deux lettres et prenez les 
	     lettres dans le coin horizontal opposé du rectangle.
         Ex : "NT" ==> "RQ" (N -> R et T -> Q)
                  \	    2	3	4
                  ---------------
                  0 |	N	A	R *
                  1 |	Y	B	D
                  2 |	G	I   K
                  3 |	Q	S   T
                        *
            
    DECHIFFREMENT
    -------------       
    Pour DECHIFFRER un message, les règles précédentes sont identiques, sauf en ce qui concerne la valeur 
	du « décalage » qui sont le contraire. Ex : ligne - 1 au lieu de ligne + 1; à gauche (-1) au lieu de 
	droite (+1) etc...
		- REGLE 1 : on retourne 2 fois le caractère situé à la (ligne - 1) et à la (colonne - 1)
		- REGLE 2 : si les 2 caractères se trouvent sur la MEME LIGNE, les remplacer par ceux se trouvant immédiatement sur leur GAUCHE.
		- REGLE 3 : si les 2 caractères se trouvent sur la MEME COLONNE, les remplacer par celles se trouvant juste au DESSUS.
		- REGLE 4 : sinon, remplacer les caractères par ceux se trouvant sur la même ligne, mais dans le coin opposé du rectangle défini par la paire originale, en commençant par la lettre sur la même ligne que la première lettre à déchiffrer.
    
	
	GÉNÉRATION DE LA GRILLE À PARTIR DE LA CLÉ
	------------------------------------------		
	- Au départ, dans la grille : ABCDEFGHIKLMNOPQRSTUVWXYZ. Si la clé est nulle ou vide alors 
	  utiliser "CIPHER". Dans tous les cas, la convertir en majuscules. Ex : "MONARCHY"
            
	- Utiliser une chaîne de travail : clé (où l'on remplace 'J' par '') + "ABCDEFGHIKLMNOPQRSTUVWXYZ" 
	  Ex : "MONARCHY" + "ABCDEFGHIKLMNOPQRSTUVWXYZ"
			
	- Pour chaque caractère correspondant au contenu initial de la grille (ABCDEFGHIKLMNOPQRSTUVWXYZ)
	  rechercher les RANGS dans la chaîne de travail.
	  Ex : pour 'A' (ligne 0, colonne 0) vs "MONARCHYABCDEFGHIKLMNOPQRSTUVWXYZ" on trouve les rangs {3,8}
			
	- Ensuite, supprimer de la chaîne de travail tous les doublos du caractère en cours de traitement.
	  Ex : pour 'A' supprimer le doublon situé au rang 8, soit "MONARCHYBCDEFGHIKLMNOPQRSTUVWXYZ" 
		
	- Une fois les 25 caractères traités, on aboutit à la dernière version de la chaîne de travail.
      Ex : "MONARCHYBDEFGIKLPQSTUVWYZ". Il s’agit alors de remplir la grille avec les 25 premiers caractères.
	  REMARQUE : pour déduire les coordonnées à partir du compteur de parcours 'i' :
				 Ligne (i/5)
				 Colonne (i%5)
				 Ex : caractère de rang i==10 (='E'). Ligne : 2 et Colonne 0
    */
    class Program
    {
        #region FONCTION PRIVEE PRINCIPALE DE CHIFFREMENT ET DECHIFFREMENT

        /* Appelée par les 2 méthodes publiques de chiffrement et dechiffrement.
        
		PARAMÈTRES :
			- Message à chiffrer
			- La clé
			- Un "flag" (booléen) permettant de connaître la tâche à traiter (chiffrement et dechiffrement)

		RETOURNE une chaîne correspondant au message chiffré ou déchiffré
        */
		private static string Traiter(string message, string cle, bool flag)
        {
            string aRetourner = string.Empty;
            char[,] grille = new char[5, 5];
            string tempMess = message.ToUpper();
            string tempCle;
            if (cle == null) tempCle = "CIPHER";
            else tempCle = cle.ToUpper().Replace("J", "I");
            string chaine = tempCle + "ABCDEFGHIKLMNOPQRSTUVWXYZ";
            #region ETAPE 1
            for (int i = 0; i < cle.Length; i++)
            {
                int[] indexes = { 0, 0 };
                indexes[0] = chaine.IndexOf(chaine[i], 0);
                indexes[1] = chaine.IndexOf(chaine[i], cle.Length);
                chaine = chaine.Remove(indexes[1], 1);
            }
            #endregion
            #region ETAPE 2
            for (int j = 0; j < tempMess.Length; j++)
            {
                char c = tempMess[j];
                if (!char.IsLetter(c) || c == ' ')
                {
                    tempMess = tempMess.Remove(j, 1);
                }
            }
            #endregion
            #region ETAPE 3
            if (tempMess.Length % 2 != 0) tempMess += 'Z';
            int m = 0;
            for (int ligne = 0; ligne < grille.GetLength(0); ligne++)
            {
                for (int colonne = 0; colonne < grille.GetLength(1); colonne++)
                {
                    grille[ligne, colonne] = chaine[m];
                    m++;
                    Console.Write($"{grille[ligne, colonne]}\t");
                }
                Console.WriteLine();
            }
            #endregion
            #region ETAPE 4
            //Découpage en PAIRE
            for (int k = 0; k <= tempMess.Length - 2; k += 2)
            {
                //Coordonnées de la PAIRE
                int[] coord1 = new int[2];
                int[] coord2 = new int[2];
                //Parcours de la grille
                for (int ligne = 0; ligne < grille.GetLength(0); ligne++)
                {
                    for (int colonne = 0; colonne < grille.GetLength(1); colonne++)
                    {
                        //Coordonnées de la première lettre
                        if (tempMess[k] == grille[ligne, colonne]) {
                            coord1[0] = ligne;
                            coord1[1] = colonne;
                        }
                        //Coordonnées de la deuxième lettre
                        if (tempMess[k + 1] == grille[ligne, colonne])
                        {
                            coord2[0] = ligne;
                            coord2[1] = colonne;
                        }
                    }

                }
                #region CHIFFREMENT
                if (flag)
                {
                    //REGLE 1
                    if (coord1[0] == coord2[0] && coord1[1] == coord2[1])
                    {
                        coord1[0] += 1;
                        coord2[0] += 1;
                        coord1[1] += 1;
                        coord2[1] += 1;
                    }

                    //REGLE 2
                    else if (coord1[0] == coord2[0])
                    {
                        coord1[1] = TestDeDepassement(coord1[1] + 1, grille);
                        coord2[1] = TestDeDepassement(coord2[1] + 1, grille);
                    }

                    //REGLE 3
                    else if (coord1[1] == coord2[1])
                    {
                        coord1[0] = TestDeDepassement(coord1[0] + 1, grille);
                        coord2[0] = TestDeDepassement(coord2[0] + 1, grille);
                    }

                    //REGLE 4
                    else
                    {
                        int t = TestDeDepassement(coord1[1], grille);
                        coord1[1] = TestDeDepassement(coord2[1], grille);
                        coord2[1] = t;
                    }
                }
                #endregion
                #region DECHIFFREMENT
                else
                {
                    //REGLE 1
                    if (coord1[0] == coord2[0] && coord1[1] == coord2[1])
                    {
                        coord1[0] -= 1;
                        coord1[1] -= 1;
                        coord2[0] -= 1;
                        coord2[1] -= 1;
                    }

                    //REGLE 2
                    else if (coord1[0] == coord2[0])
                    {
                        coord1[1] = TestDeDepassement(coord1[1] - 1, grille);
                        coord2[1] = TestDeDepassement(coord2[1] - 1, grille);
                    }

                    //REGLE 3
                    else if (coord1[1] == coord2[1])
                    {
                        coord1[0] = TestDeDepassement(coord1[0] - 1, grille);
                        coord2[0] = TestDeDepassement(coord2[0] - 1, grille);
                    }

                    //REGLE 4
                    else
                    {
                        int t = TestDeDepassement(coord1[1], grille);
                        coord1[1] = TestDeDepassement(coord2[1], grille);
                        coord2[1] = t;
                    }
                }
                #endregion
                aRetourner += $"{grille[coord1[0], coord1[1]]}{grille[coord2[0], coord2[1]]}";
            }
            #endregion
            // ...
            if(flag) Console.Write("\nTexte chiffré : "); else Console.Write("\nTexte déchiffré : "); ;
            aRetourner = RetoucherChaine(message, aRetourner);
            if (aRetourner.IndexOf('Z') != -1) aRetourner = aRetourner.Remove(aRetourner.Length - 1);
            return aRetourner;
        }

        #endregion

        #region FONCTIONS PRIVEES DIVERSES

		// ...


        // TEST DE DÉPASSEMENT (permet de traiter les "bouclements" éventuels en cas de dépassement de rang
        // en application des règles 1 à 3.
        // On fournit le rang (ligne ou colonne) et la grille (pour avoir son nombre de lignes ou de colonnes)
        // Retourne :
        //      * En cas de codage, si dépassement à "droite" : zéro
        //      * En cas de décodage, si c'était le résultat d'un bouclage alors rang == -1; 
        //        on retourne le rang de la dernière ligne ou colonne.
        //      * Sinon, on retourne le même rang.
        private static int TestDeDepassement(int rang, char[,] grille)
        {
            if (rang == grille.GetLength(0))
                return 0;
            else
            {
                // Si index == -1 c'est que l'on avait bouclé
                if (rang == -1)
                    rang = grille.GetLength(0) + rang;

                return rang;
            }
        }

        // ON RETOUCHE" LA CHAÎNE TRAITÉE (chiffrée ou déchiffrée) :
        //   - On compare caractères de même rang entre cette chaîne et le message d'origine
        //   - Si le caractère d'origine 'i' n'appartient pas à l'alphabet, on l'ajoute tel quel
        //   - Si le caractère d'origine 'i' était en minuscules alors on fait pareil dans la chaîne traitée
        // Paramètres :
        //      - input : le message à traiter
        //      - output : chaîne résultat du traitement effectué pour chaque paire, où on à concaténé la paire de substitution correspondante
        /*
        EX : sans cette fonction, 
                * Si le message en clair était "Hello World", on afficherait un message codé : "ECTTQVVGMB" au lieu de "Ecttq Vvgmb"
                * Si le message chiffré était "ECTTQVVGMB", on afficherait un message en clair : "HELLOWORLD" au lieu de "Hello World"
        */
        private static string RetoucherChaine(string input, string output)
        {
            StringBuilder aRetourner = new StringBuilder(output);
            // Parcours autant de fois qu'il y a de caractères dans le message à traiter
            for (int i = 0; i < input.Length; ++i)
            {
                // On est sur un caractère qui n'appartient pas à l'alphabet
                // On ajoute ce caractère à la chaîne traitée, au rang 'i'
                if (!char.IsLetter(input[i]))
                    aRetourner = aRetourner.Insert(i, input[i].ToString());

                // Si le caractère 'i' du message d'origine est en minuscule, 
                // on le remplace par la version minuscule du caractère de même rang dans la chaîne traitée
                if (char.IsLower(input[i]))
                    aRetourner[i] = char.ToLower(aRetourner[i]);
            }

            return aRetourner.ToString();
        }

        #endregion

        #region FONCTIONS PUBLIQUES

        // PARAMÈTRES :
        //    - Message à chiffrer
        //    - La clé symétrique
        // Les 2 méthodes appelent une méthode unique : "Traiter()" en transmettant à leur tour 
        // les paramètres, plus un booléen comme "flag" (VRAI pour chiffrer, FAUX pour déchiffrer)
        public static string Chiffrer(string texte, string cle)
        {
            return Traiter(texte, cle, true);
        }

        public static string Dechiffrer(string texte, string cle)
        {
            return Traiter(texte, cle, false);
        }

        #endregion

        static void Main(string[] args)
        {
            /*
            cipherText:	"Ecttq Vvgmb"
            plainText:	"Hello World"
            */
            //string texte = "Hello World";
            string cle = "cipher";
            string[] lesTextes = new string[] 
            { 
                "Hello World", "General Mac Mahon","Pilonage le huit de huit a midi", "Attaque Malakoff a midi",
                "Par Premier Reg Zouaves", "Et Septieme Reg Infanterie", "Signe General Pelissier"
            };
            foreach(string texte in lesTextes)
            {
                string texte_chiffre = Chiffrer(texte, cle);
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(texte_chiffre + "\n");
                Console.ForegroundColor = ConsoleColor.White;
                string texte_dechiffre = Dechiffrer(texte_chiffre, cle);
                Console.ForegroundColor = ConsoleColor.Blue;
                Console.WriteLine(texte_dechiffre + "\n");
                Console.ForegroundColor = ConsoleColor.White;
                Console.ReadKey();
                Console.Clear();
            }
            Console.ReadKey();
        }
    }
}
