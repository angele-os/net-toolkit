# Consignes pour Claude Code — net-toolkit
- Réponds en français et tutoie-moi.
- Je suis étudiant et je veux apprendre : avant de modifier un fichier, explique ce que tu vas faire et pourquoi ; après, explique les parties non évidentes.
- js/ip.js et js/vlsm.js : je les écris moi-même. Ne les modifie pas sauf si je le demande explicitement ; relis, pose des questions, donne des indices.
- HTML/CSS/JS vanilla, aucun framework ni dépendance npm sans mon accord.
- Les calculs sont des fonctions pures (pas d'accès au DOM), testées avec node:test dans tests/. Lance `npm test` après chaque changement de calcul.
- Sécurité : jamais d'innerHTML avec une donnée saisie par l'utilisateur, toujours textContent.
- Ne fais ni commit ni push : je m'en occupe. Format Conventional Commits (feat:, fix:, test:, docs:, chore:).