# Consignes pour Claude Code — net-toolkit

## Qui je suis
- Étudiant en BUT Informatique (réseaux et cybersécurité). Je débute complètement en programmation.
- Réponds en français et tutoie-moi.

## Comment travailler avec moi
- C'est toi qui écris le code ; mon objectif est de le comprendre.
- Avant de modifier : explique simplement ce que tu vas faire et pourquoi. Si tu utilises un terme technique, explique-le.
- Après : résume le rôle de chaque fichier modifié, puis les 2 ou 3 idées importantes à retenir, avec un exemple tiré du réseau.
- Commente le code en français ; pour les calculs, commente chaque ligne.
- Une seule étape à la fois.

## Règles techniques
- HTML, CSS et JavaScript vanilla : aucun framework, aucune dépendance npm.
- Les calculs (js/ip.js, js/vlsm.js) sont des fonctions pures, sans accès à la page, testées avec node:test dans tests/. Lance `npm test` après chaque changement et corrige jusqu'à ce que tout passe.
- Sécurité : jamais d'innerHTML avec une donnée saisie par l'utilisateur, toujours textContent. Aucun secret dans le dépôt : il est public.
- Ne fais ni commit ni push : je m'en occupe. Propose-moi un message au format Conventional Commits (feat:, fix:, test:, docs:, chore:).