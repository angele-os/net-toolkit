# Politique de sécurité

> **English summary.** net-toolkit is a static, client-side IPv4/VLSM calculator and Cisco configuration generator: no server, no database, no account, no cookie, and no data ever leaves the browser. To report a vulnerability, please use GitHub's **private vulnerability reporting** ([Security → Report a vulnerability](https://github.com/angele-os/net-toolkit/security/advisories/new)) instead of a public issue. The page ignores the URL entirely: the shareable-link feature was deliberately removed to reduce the attack surface, so no outside data enters the page. The threat model below covers XSS (textContent only, strict CSP with Trusted Types), **command injection into the generated Cisco configuration** (strict allow-lists on every text field, addresses and ports re-written from parsed numbers, a final printable-ASCII check on every output line, and dedicated injection tests), **no passwords requested** (every secret is a `<A_REMPLACER>` placeholder to fill in by hand; pasted unchanged, the password literally becomes that public placeholder), the requirement to **review and test the generated configuration before any real use**, CSV/formula injection (OWASP-style escaping, unit-tested), oversized input (length limits in both the pure functions and the HTML), invisible/bidirectional Unicode characters (Cc/Cf categories rejected), supply chain (zero npm dependencies, self-hosted fonts, SHA-pinned GitHub Actions updated by Dependabot), deployment to GitHub Pages (allow-listed site files only, deployed only when tests pass, write permissions and a short-lived OIDC token limited to the deploy job), secret leakage, accepted clickjacking risk, and subdomain takeover.

## Signaler une faille

Merci de **ne pas ouvrir d'issue publique** pour une faille : elle serait visible de tous avant d'être corrigée.

Utilise le **signalement privé de GitHub** : onglet **Security** du dépôt, puis **Report a vulnerability**, ou directement :
<https://github.com/angele-os/net-toolkit/security/advisories/new>

Indique si possible :
- la version concernée (le hash du commit ou la date) et le navigateur utilisé ;
- les étapes pour reproduire le problème (la saisie exacte, le fichier CSV produit…) ;
- l'impact que tu envisages.

C'est un projet personnel, maintenu sur mon temps libre. J'essaie de répondre sous 7 jours, sans garantie. Seule la dernière version de la branche `main` est maintenue.

## Modèle de menace

### Ce que l'outil est (et n'est pas)

- **Une page web statique.** HTML, CSS et JavaScript sont exécutés entièrement dans le navigateur.
- **Aucune donnée n'est envoyée ni stockée.** Il n'y a pas de serveur applicatif, pas de base de données, pas de compte, pas de cookie, pas de `localStorage`. La CSP l'impose techniquement : `default-src 'none'` sans `connect-src` interdit toute requête réseau depuis le JavaScript.
- **Aucune donnée extérieure n'entre dans la page.** Les seules entrées sont les champs du formulaire. L'adresse de la page (y compris ce qui suit le `#`) est ignorée : aucun code ne lit `location` ni l'historique, ce que vérifie un test.
- **Ce qu'on protège :** le navigateur de la personne qui utilise l'outil, l'ordinateur de la personne qui ouvre un CSV exporté, l'équipement réseau (switch, routeur) sur lequel on colle une configuration générée, et l'intégrité du code publié.

### Risques et protections

| Risque | Applicable ? | Protection mise en place |
|---|---|---|
| Injection SQL | Non | Pas de base de données |
| XSS (injection de script) | Oui | `textContent` uniquement, CSP stricte, Trusted Types |
| Lien partageable | Retiré | Fonctionnalité retirée volontairement pour réduire la surface d'attaque (aucune donnée extérieure n'entre dans la page) |
| Injection CSV (formules) | Oui | Apostrophe devant `= + - @` tabulation retour chariot, guillemets |
| Injection de commandes dans la configuration générée | Oui | Listes blanches strictes, adresses et ports réécrits par le programme, contrôle final de chaque ligne, tests d'injection |
| Mots de passe dans la configuration | Évité | Aucun mot de passe demandé : marqueurs `<A_REMPLACER>` à remplir à la main |
| Configuration erronée appliquée à un équipement réel | Oui | Avertissement visible : relire et tester avant tout usage réel |
| Saisies énormes | Oui | Limites dans les fonctions pures **et** `maxlength` |
| Caractères invisibles | Oui | Catégories Unicode Cc et Cf refusées dans les noms ; ASCII seul dans la configuration Cisco |
| Chaîne d'approvisionnement | Oui | 0 dépendance npm, polices auto-hébergées, actions épinglées par SHA + Dependabot |
| Publication du site | Oui | Liste blanche des fichiers publiés, déploiement seulement si les tests passent, droits d'écriture limités au job deploy |
| Fuite de secrets | Faible | Aucun secret nécessaire, jeton CI en lecture seule |
| Clickjacking | Risque accepté | Voir justification |
| Vol de sous-domaine | À la mise en ligne | Domaine vérifié, ordre de suppression DNS |

#### Injection SQL : non applicable

L'injection SQL consiste à glisser du code SQL dans une saisie pour qu'un serveur l'exécute sur sa base de données. net-toolkit n'a **ni serveur ni base de données** : aucune requête SQL n'existe, il n'y a donc rien à injecter. Si une base de données était ajoutée un jour, il faudrait utiliser des requêtes paramétrées.

#### XSS (Cross-Site Scripting)

Le risque : une saisie (par exemple un nom de sous-réseau) contenant du HTML ou du JavaScript serait interprétée par la page.

Les protections :
- **Aucun `innerHTML`.** Tout texte est inséré avec `textContent`, qui affiche les caractères tels quels : résultats, noms de sous-réseaux repris dans le générateur Cisco, et configurations affichées dans les blocs `<pre>`. La ligne de besoin et la ligne de VLAN sont des `<template>` HTML clonés avec `cloneNode`. Un test vérifie qu'aucun fichier JavaScript n'utilise `innerHTML`, `outerHTML`, `insertAdjacentHTML` ou `document.write`.
- **CSP stricte** (balise `<meta>`) : `default-src 'none'; script-src 'self'; style-src 'self'`. Aucun script ni style en ligne, aucun `onclick="…"`, pas d'`eval`.
- **Trusted Types** : `require-trusted-types-for 'script'; trusted-types 'none'`. Le navigateur refuse toute écriture de texte dans une fonction dangereuse (`innerHTML`, `eval`…), même si du code en ajoutait une par erreur plus tard. Cette directive est appliquée par les navigateurs qui la prennent en charge.
- **`base-uri 'none'`** (empêche de détourner les liens relatifs avec une balise `<base>`) et **`object-src 'none'`** (pas de plugins).
- Un test (`tests/html.test.js`) vérifie que la CSP contient ces directives et que le HTML ne contient aucun script, style ou gestionnaire d'événement en ligne.

#### Injection CSV (injection de formule)

Le risque : un nom de sous-réseau comme `=HYPERLINK("http://pirate.example";"Clique")` serait exécuté comme une formule quand le CSV exporté est ouvert dans Excel ou LibreOffice.

La protection (`js/export.js`, testée dans `tests/export.test.js`), conforme aux recommandations OWASP sur la *CSV Injection* :
- une cellule qui commence par `=`, `+`, `-`, `@`, une tabulation ou un retour chariot est **préfixée d'une apostrophe**, et le tableur l'affiche alors comme du texte ;
- une cellule qui contient `;`, `"` ou un retour à la ligne est **entourée de guillemets**, et ses `"` sont doublés. Sans ça, `a;=1+1` serait coupé en deux cellules, la seconde étant une formule ;
- la copie dans le presse-papiers applique la même protection.

Compromis accepté : un nom qui commence légitimement par `-` (par exemple `-Serveurs`) apparaît avec une apostrophe dans le tableur.

#### Injection de commandes dans la configuration générée

Le risque : c'est le risque principal du générateur Cisco. Une configuration IOS se lit **ligne par ligne**, et chaque ligne est une commande. Si un nom de VLAN valait `Bureau` suivi d'un retour à la ligne puis de `username pirate privilege 15 secret 0 1234`, la configuration collée sur le switch créerait un compte administrateur pirate. D'autres caractères sont dangereux : le délimiteur de la bannière (`banner motd #texte#` : un `#` dans le texte ferme la bannière, et la suite devient des commandes), `?` (la console IOS affiche l'aide au lieu de l'écrire), ou les retours à la ligne Unicode comme U+2028.

Les protections (`js/cisco.js`, testées dans `tests/cisco.test.js`) :
- **Listes blanches strictes.** On décrit les caractères permis et on refuse tout le reste, ce qui est plus sûr que de chercher les caractères dangereux (une liste noire en oublie toujours un) :

  | Champ | Caractères autorisés | Longueur |
  |---|---|---|
  | Hostname | une lettre, puis lettres sans accent, chiffres, `-` | 63 |
  | Nom de VLAN | lettres sans accent, chiffres, `_`, `-` | 32 |
  | Nom de domaine | mots de lettres sans accent, chiffres, `-`, séparés par des points | 64 |
  | Bannière | lettres sans accent, chiffres, espace, `. , ; : ! ' ( ) / @ + = * _ -` (ni `#` ni `?`) | 200 |
  | Plage de ports | `Fa0/n`, `Fa0/n-m`, `Gi0/n` : seulement les ports qui existent sur le 2960-24TT | 20 |

- **Rien de saisi n'est recopié tel quel.** Les adresses IP, sous-réseaux, ports et numéros de VLAN sont relus en nombres, puis c'est le programme qui les réécrit dans la configuration. Un sous-réseau suivi d'un retour à la ligne et d'une commande est refusé.
- **Validations de cohérence** avec des messages clairs : numéros de VLAN de 2 à 4094 hors 1002-1005, sans doublon, différents du VLAN natif et du VLAN parking ; ports sans chevauchement ; sous-réseaux sans chevauchement ; passerelle dans son sous-réseau.
- **Dernier filet (défense en profondeur).** La configuration est écrite entièrement en ASCII : chaque ligne produite ne doit contenir que des caractères ASCII visibles ou des espaces. Sinon, la génération est refusée plutôt que livrée. Ce filet bloque aussi U+2028, que la liste blanche refuse déjà.
- **Tests d'injection.** Vingt-quatre tentatives doivent être refusées : retour à la ligne (y compris final), retour chariot, `!`, U+2028, U+0085, caractère nul, échappement de terminal, tabulation, U+202E, bannière qui se ferme avec `#` puis enchaîne une commande, Ctrl+C dans la bannière, commande glissée après une plage de ports, un port trunk, un sous-réseau, une passerelle, un DNS ou un mode de violation. Le message d'erreur nomme le caractère refusé par son code (« U+000A ») sans le recopier.
- **Non-régression.** La configuration d'un scénario de référence est comparée, caractère par caractère, à deux fichiers attendus (`tests/fixtures/`).

#### Aucun mot de passe demandé

Le générateur ne demande **aucun mot de passe** et n'en écrit aucun. Chaque secret (`enable secret`, compte local `username … secret …`) est un marqueur `<A_REMPLACER>`, accompagné d'un commentaire `! SECRET` qui explique quoi mettre.

Pourquoi :
- un mot de passe saisi dans une page web peut fuir : historique du presse-papiers, fichier `.txt` téléchargé puis partagé, capture d'écran, configuration envoyée par messagerie. Le meilleur moyen de ne pas le divulguer est de ne jamais le connaître ;
- la configuration générée est faite pour être relue et partagée (dans un ticket, une documentation) : elle ne doit contenir aucun secret ;
- les secrets sont stockés sous forme de hachage (`secret` et non `password`), et la configuration signale en commentaire la variante plus robuste `enable algorithm-type scrypt secret`, que Packet Tracer ne prend pas en charge.

**Limite connue :** IOS accepte `<A_REMPLACER>` comme mot de passe. Une configuration collée sans remplacer les marqueurs fonctionne donc, mais avec un mot de passe **public**, puisqu'il figure dans ce dépôt. Cela a été constaté lors du test dans Packet Tracer. C'est acceptable sur une maquette, jamais sur un équipement réel. Le fichier de démonstration `docs/packet-tracer/net-toolkit-siege.pkt` contient d'ailleurs ces marqueurs non remplacés, et aucun autre mot de passe.

#### Configuration à relire avant tout usage réel

Le générateur produit un **point de départ**, pas une configuration garantie pour un réseau de production. Elle a été testée dans Cisco Packet Tracer (trunk, VLAN, Port Security, DHCP, routage entre VLAN), mais pas sur du matériel physique, et chaque réseau a ses contraintes. Un encadré visible, au-dessus des configurations, rappelle donc :

> Configuration à relire et à tester (par exemple dans Packet Tracer) avant tout usage sur un équipement réel. Remplace les marqueurs `<A_REMPLACER>`.

Points d'attention avant de la coller :
- remplacer **tous** les marqueurs `<A_REMPLACER>` ;
- coller dans un équipement **neuf ou réinitialisé** : si une clé RSA existe déjà, `crypto key generate rsa` pose une question, et la ligne collée suivante sert de réponse ;
- le VLAN de management est joignable depuis tous les VLAN. Une ACL sur les lignes VTY, absente pour l'instant, limiterait l'accès SSH aux postes d'administration ;
- les ports Fa0/1 à Fa0/24 sont répartis à parts égales par défaut : à adapter au câblage réel.

#### Saisies énormes

Le risque : coller un texte de plusieurs mégaoctets, ou demander des milliers de sous-réseaux, pour bloquer l'onglet ou remplir l'écran de messages d'erreur.

Les protections, appliquées **dans les fonctions pures** (même si l'on contourne l'interface) **et** dans le HTML (`maxlength`, pour le confort) :

| Saisie | Limite |
|---|---|
| Adresse IP ou réseau | 40 caractères |
| Nom d'un besoin | 32 caractères |
| Nombre d'hôtes | 10 chiffres (9 999 999 999) |
| Nombre de besoins | 256 (le bouton « Ajouter » se désactive avec un message) |
| Hostname (générateur Cisco) | 63 caractères |
| Nom de VLAN | 32 caractères |
| Nom de domaine | 64 caractères |
| Bannière | 200 caractères |
| Plage de ports | 20 caractères |
| Nombre de VLAN | 25 (un port access chacun, plus le port trunk) |

Autres précautions :
- la longueur est vérifiée **avant** tout traitement, et les messages d'erreur ne recopient pas un texte trop long ;
- les expressions régulières sont simples (pas de répétitions imbriquées), donc sans risque de ReDoS, un blocage dû à une expression régulière qui s'emballe ;
- un test vérifie que les `maxlength` du HTML restent égaux aux limites des fonctions pures.

#### Caractères invisibles et de contrôle

Le risque : un nom contenant des caractères Unicode invisibles trompe la personne qui lit le résultat ou le CSV. Par exemple, U+202E (*Right-to-Left Override*) inverse l'affichage de la suite du texte : c'est la technique « Trojan Source », CVE-2021-42574. D'autres exemples sont U+200B (espace sans chasse) ou les caractères de contrôle comme U+001B (échappement).

La protection (`erreurNom` dans `js/vlsm.js`) : tout nom qui contient un caractère des catégories Unicode **Cc** (contrôle) ou **Cf** (mise en forme invisible) est refusé. Le message d'erreur donne le **code** du caractère (« U+202E ») sans le recopier, pour ne pas retourner l'affichage du message lui-même.

Compromis accepté : les emojis composés avec le liant U+200D (par exemple 👩‍💻) sont refusés. Les emojis simples sont acceptés.

Dans le générateur Cisco, la règle est plus stricte : les listes blanches n'acceptent que des caractères ASCII visibles (voir « Injection de commandes »). Un nom de sous-réseau avec accents ou emojis, repris du plan VLSM, est converti en nom de VLAN sans accent (`Wi-Fi invités` devient `Wi-Fi_invites`).

Un test vérifie enfin qu'aucun fichier du code source (`index.html`, `404.html`, `css/`, `js/`, `tests/` et `tests/fixtures/`) ne contient lui-même de caractère invisible.

#### Chaîne d'approvisionnement

Le risque : du code malveillant arrive par une dépendance, un CDN ou un outil d'intégration continue compromis.

Les protections :
- **Aucune dépendance npm**, ni à l'exécution ni pour les tests (`node:test` est intégré à Node.js). `"private": true` dans `package.json` empêche une publication accidentelle sur npm.
- **Aucune ressource externe** : les polices sont auto-hébergées dans `fonts/` (licence SIL OFL 1.1), et la CSP (`'self'`) bloque tout CDN.
- **GitHub Actions épinglées par empreinte SHA complète** (avec la version en commentaire). Contrairement à une étiquette comme `v7`, un SHA ne peut pas être déplacé vers un autre code. Un test (`tests/ci.test.js`) vérifie que chaque `uses:` des workflows respecte cette règle.
- **Dependabot** (`.github/dependabot.yml`) propose chaque semaine les mises à jour de ces actions, à relire avant de fusionner.
- Le workflow de tests s'exécute avec **`permissions: contents: read`** et utilise l'évènement `pull_request` (et non `pull_request_target`) : une pull request venant d'un fork ne reçoit ni secret ni droit d'écriture.

#### Publication du site (GitHub Pages)

Le risque : publier par erreur un fichier qui ne devrait pas l'être (fichier de configuration, brouillon, secret oublié), publier une version cassée, ou qu'un job compromis modifie le site.

Les protections (`.github/workflows/deploy.yml`) :
- **Publication limitée aux fichiers du site, par liste blanche.** Le job `build` copie dans `_site` uniquement `index.html`, `404.html`, `favicon.svg`, `robots.txt`, `sitemap.xml`, `css/`, `js/` et `fonts/`. Les tests, la documentation (`docs/`, dont le fichier Packet Tracer), la configuration (`package.json`, `.github/`, `CLAUDE.md`…) et tout fichier ajouté plus tard au dépôt ne sont **jamais** publiés sans modification explicite de cette liste. La liste des fichiers publiés est affichée dans le journal du workflow.
- **Déploiement conditionné aux tests.** Le job `deploy` ne démarre que si les jobs `test` et `build` ont réussi (`needs: [test, build]`) : une version qui casse un test n'est jamais mise en ligne.
- **Permissions minimales par job.** `test` et `build` n'ont que `contents: read`. Seul `deploy` reçoit `pages: write` (publier sur Pages) et `id-token: write` (obtenir un jeton d'identité OIDC à courte durée de vie, prouvant à GitHub Pages que le déploiement vient bien de ce workflow). Ce job n'exécute aucun code du dépôt : il ne fait que publier l'archive préparée par `build`.
- **Aucun secret stocké** : l'authentification auprès de Pages passe par ce jeton OIDC temporaire, et `persist-credentials: false` est utilisé à chaque `checkout`.
- **Un seul déploiement à la fois** (`concurrency`), sans annuler celui en cours, pour ne jamais laisser un site à moitié publié.
- **Environnement `github-pages`** : GitHub y enregistre l'historique des déploiements, et ses règles de protection (réglages du dépôt) peuvent limiter les déploiements à la branche `main`.

#### Fuite de secrets

Le risque : une clé ou un mot de passe publié dans ce dépôt public, ou volé pendant l'intégration continue.

Les protections :
- l'outil **n'a besoin d'aucun secret** : pas d'API, pas de clé, pas de compte ;
- le générateur Cisco ne demande aucun mot de passe (voir « Aucun mot de passe demandé »), et le fichier Packet Tracer publié dans `docs/` ne contient que les marqueurs `<A_REMPLACER>` ;
- `.gitignore` exclut les fichiers `.env` ;
- dans les workflows, le jeton GitHub est en **lecture seule**, sauf pour le job de publication qui peut seulement écrire sur GitHub Pages (voir « Publication du site »), et `persist-credentials: false` évite de le laisser dans la configuration git de la machine virtuelle ;
- côté utilisateur, les saisies ne quittent jamais le navigateur (pas de `connect-src`).

#### Clickjacking : risque accepté

Le risque : un site malveillant affiche net-toolkit dans une `<iframe>` invisible et pousse l'utilisateur à cliquer dessus sans le savoir.

La protection habituelle (`frame-ancestors` dans l'en-tête HTTP CSP, ou `X-Frame-Options`) **ne peut pas être définie dans une balise `<meta>`**. Il faut un en-tête HTTP, ce que les hébergeurs statiques comme GitHub Pages ne permettent pas de configurer.

Le risque est **accepté** parce que l'outil n'a **aucune action sensible** : pas de compte, pas de session, pas d'achat, pas de suppression, pas de données personnelles. Le pire qu'un clic piégé puisse faire est de lancer un calcul ou de télécharger un CSV de calcul réseau. Si l'outil est un jour hébergé avec des en-têtes configurables, il faudra ajouter `Content-Security-Policy: frame-ancestors 'none'`.

#### Vol de sous-domaine (subdomain takeover)

Le risque : l'outil est prévu sur le sous-domaine `reseau.ange-bonkoski.fr`. S'il est publié via un enregistrement DNS `CNAME` vers GitHub Pages, puis que le site est supprimé **sans retirer l'enregistrement DNS**, quelqu'un d'autre peut réclamer ce sous-domaine sur son propre compte GitHub Pages et y publier le contenu de son choix sous mon nom de domaine.

Les protections, à appliquer lors de la mise en ligne :
- **vérifier le domaine** dans les réglages GitHub du compte (*Settings → Pages → Verified domains*) : seul mon compte peut alors l'utiliser ;
- **ne jamais utiliser d'enregistrement DNS générique** (`*.ange-bonkoski.fr`) pointant vers GitHub Pages ;
- en cas d'arrêt du site, **supprimer d'abord l'enregistrement DNS**, puis désactiver GitHub Pages, jamais dans l'autre sens.

### Hors périmètre

- Les attaques qui supposent un ordinateur ou un navigateur déjà compromis (extension malveillante, logiciel espion).
- Une personne qui saisit elle-même des données trompeuses et ne les montre qu'à elle-même (*self-XSS*).
- Les erreurs de calcul réseau, ou une commande Cisco refusée ou mal adaptée : ce sont des bugs à signaler dans une issue publique, pas des failles de sécurité. En revanche, une saisie qui fait apparaître une commande **non prévue** dans la configuration générée est une faille : à signaler en privé.
- L'usage d'une configuration générée sans l'avoir relue, ou avec les marqueurs `<A_REMPLACER>` non remplacés.
