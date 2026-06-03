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

10) Regenerer juste le rapport HTML depuis les CSV existants (sans re-auditer) :
   python ltspice_lib_auditor.py --out "C:\Temp\lt_audit" --report-only

11) Lancer l'interface graphique :
   python ltspice_lib_auditor.py --gui
   (les chemins et options du dernier run sont rappeles automatiquement)

12) Desactiver le groupement (test individuel par sous-circuit, plus lent mais
    plus simple a tracer) :
   python ltspice_lib_auditor.py --root "..." --out "C:\Temp\lt_audit" --group-size 1

13) Generer un fix bundle a partager (avec Claude par exemple) :
   python ltspice_lib_auditor.py --root "..." --out "C:\Temp\lt_audit" --fix-bundle
   # ou depuis un audit deja realise :
   python ltspice_lib_auditor.py --out "C:\Temp\lt_audit" --fix-bundle-only

14) Bundle limite aux corrections deterministes (.ENDS manquant, INCLUDE...) :
   python ltspice_lib_auditor.py --out "C:\Temp\lt_audit" --fix-bundle-only \
       --bundle-min-confidence high --bundle-max-files 80

Options principales :
- -j N / --jobs N        : nb de processus paralleles (defaut auto = cpu-1)
- --timeout N            : timeout LTspice en secondes (defaut 15)
- --group-size N         : sous-circuits par deck groupe (defaut 20 ; 1 = desactive).
                           Si un groupe echoue, fallback automatique sur tests individuels.
- --no-cache             : ignore + n'ecrit pas le cache .audit_cache.json
- --keep-raw             : conserve les .raw / .net (par defaut supprimes)
- --only-suspect         : batch limite aux SUSPECT/BROKEN_LIKELY/READ_ERROR
- --skip-broken-batch    : saute les BROKEN_LIKELY/READ_ERROR au batch
- --max-files / --max-subckts : limites pour tester rapidement
- --no-report            : pas de rapport HTML en fin d'audit
- --report-only          : regenere uniquement report.html depuis les CSV
- --gui                  : lance l'interface graphique Tkinter
- --fix-bundle           : genere fix_bundle/ a la fin de l'audit
- --fix-bundle-only      : regenere uniquement le bundle depuis les CSV existants
- --bundle-max-files N   : cap du nb de fichiers dans le bundle (defaut 100)
- --bundle-min-confidence : high | medium | low | manual_only (defaut low)

Sorties importantes :
- reports/files_summary.csv
- reports/static_issues.csv
- reports/subckts.csv
- reports/models.csv
- reports/batch_commands.csv
- reports/batch_results.csv
- README_AUDIT.txt
- report.html         (rapport interactif filtrable, ouvre dans un navigateur)
- fix_bundle/         (genere si --fix-bundle ; pret a partager)
- .audit_cache.json   (cache : evite de retester ce qui n'a pas bouge)

Rapport HTML (report.html) :
- Fichier autonome, fonctionne offline (pas de CDN)
- Cartes de stats globales + recommandations actionnables
- Repartition par statut (prescan + batch)
- Top categories d'erreurs LTspice
- Inventaire pour la reorganisation : extensions, types de .MODEL, pin counts
- Tables triables (click sur les en-tetes) et filtrables (champ recherche)
- Genere automatiquement a la fin de chaque audit (sauf --no-report)

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
- Le groupement (--group-size 20 par defaut) teste 20 sous-circuits par
  invocation LTspice : amortit le startup process (~2-5s sur Windows). En cas
  d'echec d'un groupe, fallback automatique sur tests individuels pour
  identifier le coupable.
- Combiner -j (parallelisme) + --timeout court + --only-suspect + groupement
  donne en general un gain de 30-100x sur les grosses librairies.

Interface graphique (--gui) :
- Formulaire avec selecteurs de fichiers/dossiers
- Cases a cocher pour toutes les options
- Spinbox pour workers / timeout / group-size / max-*
- Console scrollable temps reel avec coloration syntaxique
- Barre de progression + ETA + debit (tests/min)
- Bouton Arreter qui sauve le cache avant de tuer le process
- Boutons "Ouvrir rapport HTML" et "Ouvrir dossier sortie"
- Reglages persistes dans ~/.ltspice_audit_gui_settings.json

Fix bundle (--fix-bundle) :
- Genere un dossier portable {out}/fix_bundle/ contenant :
  - sources/         : copies 1:1 des fichiers en erreur, arborescence preservee
  - logs/            : logs LTspice complets pour chaque echec batch
  - errors.json      : donnees structurees (chemin, categorie, log_excerpt,
                       confiance auto-fix par fichier)
  - MANIFEST.md      : explications + workflow recommande
  - bundle_summary.txt : 1 ligne par fichier, lisible humain
- Niveaux de confiance assignes automatiquement :
  - high          : correction mecanique (.ENDS manquant, FAIL_INCLUDE...)
  - medium        : probablement corrigeable, a verifier
  - low           : necessite contexte / datasheet
  - manual_only   : TIMEOUT, FATAL, fichiers chiffres (heuristique conservatrice)
- Fichiers chiffres : detectes par marqueur ENCRYPTED ou ratio binaire eleve,
  NON copies dans sources/ (mais listes dans errors.json avec note).
- Fichiers > 1 Mo : non copies par defaut (note ajoutee).
- Workflow recommande :
  1. python ltspice_lib_auditor.py --out ... --fix-bundle-only
                                   --bundle-min-confidence high
  2. zip fix_bundle/ -> partage avec Claude
  3. Applique les fichiers corriges, relance l'audit, le cache fait le reste.
