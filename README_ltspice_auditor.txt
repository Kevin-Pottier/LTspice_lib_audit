LTspice Library Auditor - mode d'emploi rapide
==============================================

1) Installe Python 3.10+ sur Windows.

2) Place le script où tu veux, par exemple :
   C:\Users\kpottier\Desktop\ltspice_lib_auditor.py

3) Exemple de lancement simple :
   python ltspice_lib_auditor.py --root "C:\Users\kpottier\AppData\Local\LTspice\lib\thirdparty\bordodynov" --out "C:\Temp\lt_audit"

4) Si LTspice n'est pas détecté automatiquement :
   python ltspice_lib_auditor.py --root "C:\Users\kpottier\AppData\Local\LTspice\lib\thirdparty\bordodynov" --out "C:\Temp\lt_audit" --ltspice "C:\Program Files\ADI\LTspice\LTspice.exe"

5) Si tu veux seulement générer les decks et les commandes :
   python ltspice_lib_auditor.py --root "C:\Users\kpottier\AppData\Local\LTspice\lib\thirdparty\bordodynov" --out "C:\Temp\lt_audit" --no-batch

6) Si tu veux tester seulement les fichiers suspects :
   python ltspice_lib_auditor.py --root "C:\Users\kpottier\AppData\Local\LTspice\lib\thirdparty\bordodynov" --out "C:\Temp\lt_audit" --only-suspect

Sorties importantes :
- reports/files_summary.csv
- reports/static_issues.csv
- reports/subckts.csv
- reports/models.csv
- reports/batch_commands.csv
- reports/batch_results.csv
- README_AUDIT.txt

Interprétation :
- LIKELY_OK      : rien de grave vu au prescan
- SUSPECT        : des motifs douteux existent
- BROKEN_LIKELY  : très forte probabilité d'erreur structurelle
- FAIL_SYNTAX    : LTspice a rencontré une erreur de syntaxe
- FAIL_INCLUDE   : dépendance manquante
- FAIL_SUBCKT    : sous-circuit non instanciable
- FAIL_PINCOUNT  : problème de nombre de broches
