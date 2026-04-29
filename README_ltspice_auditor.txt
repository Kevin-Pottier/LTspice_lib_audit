LTspice Library Auditor - mode d'emploi rapide
==============================================

1) Installe Python 3.10+ sur Windows.

2) Place le script ou tu veux 

3) Exemple de lancement simple (parallelisme auto = nb_coeurs - 1) :
   python ltspice_lib_auditor.py --root "{PATH_TO_LIB}" --out "C:\Temp\lt_audit"

4) Si LTspice n'est pas detecte automatiquement :
   python ltspice_lib_auditor.py --root "..." --out "C:\Temp\lt_audit" --ltspice "C:\Program Files\ADI\LTspice\LTspice.exe"

5) Forcer 8 workers paralleles et un timeout court :
   python ltspice_lib_auditor.py --root "..." --out "C:\Temp\lt_audit" -j 8 --timeout 10

6) Si tu veux seulement generer les decks et les commandes (pas de run LTspice) :
   python ltspice_lib_auditor.py --root "..." --out "C:\Temp\lt_audit" --no-batch

7) Tester seulement les fichiers suspects (le plus rentable en perf) :
   python ltspice_lib_auditor.py --root "..." --out "C:\Temp\lt_audit" --only-suspect

8) Sauter aussi les fichiers deja juges casses au prescan :
   python ltspice_lib_auditor.py --root "..." --out "C:\Temp\lt_audit" --skip-broken-batch

9) Forcer un rescan complet sans utiliser le cache :
   python ltspice_lib_auditor.py --root "..." --out "C:\Temp\lt_audit" --no-cache

Options principales :
- -j N / --jobs N        : nb de processus paralleles (defaut auto = cpu-1)
- --timeout N            : timeout LTspice en secondes (defaut 15)
- --no-cache             : ignore + n'ecrit pas le cache .audit_cache.json
- --keep-raw             : conserve les .raw / .net (par defaut supprimes)
- --only-suspect         : batch limite aux SUSPECT/BROKEN_LIKELY/READ_ERROR
- --skip-broken-batch    : saute les BROKEN_LIKELY/READ_ERROR au batch
- --max-files / --max-subckts : limites pour tester rapidement

Sorties importantes :
- reports/files_summary.csv
- reports/static_issues.csv
- reports/subckts.csv
- reports/models.csv
- reports/batch_commands.csv
- reports/batch_results.csv
- README_AUDIT.txt
- .audit_cache.json   (cache : evite de retester ce qui n'a pas bouge)

Interpretation :
- LIKELY_OK      : rien de grave vu au prescan
- SUSPECT        : des motifs douteux existent
- BROKEN_LIKELY  : tres forte probabilite d'erreur structurelle
- FAIL_SYNTAX    : LTspice a rencontre une erreur de syntaxe
- FAIL_INCLUDE   : dependance manquante
- FAIL_SUBCKT    : sous-circuit non instanciable
- FAIL_PINCOUNT  : probleme de nombre de broches
- TIMEOUT        : LTspice n'a pas rendu la main dans --timeout secondes
- EXEC_ERROR     : echec de lancement du process

Performance :
- Le cache est indexe par hash de fichier : un 2eme run ne refait que les
  fichiers modifies depuis le run precedent.
- En cas de crash / Ctrl+C, le cache est sauvegarde periodiquement, donc
  relancer la meme commande reprend la ou ca s'est arrete.
- Combiner -j (parallelisme) + --timeout court + --only-suspect donne en
  general un gain de 10-20x sur les grosses librairies.
