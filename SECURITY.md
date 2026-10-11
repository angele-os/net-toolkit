# Politique de sécurité

> **English summary.** net-toolkit is a static, client-side IPv4/VLSM calculator: no server, no database, no account, no cookie, and no data ever leaves the browser. To report a vulnerability, please use GitHub's **private vulnerability reporting** ([Security → Report a vulnerability](https://github.com/angele-os/net-toolkit/security/advisories/new)) instead of a public issue. The threat model below covers XSS (textContent only, strict CSP with Trusted Types), crafted shareable links (the URL fragment is treated as untrusted input and validated like form fields), CSV/formula injection (OWASP-style escaping, unit-tested), oversized input (length limits in both the pure functions and the HTML), invisible/bidirectional Unicode characters (Cc/Cf categories rejected), supply chain (zero npm dependencies, self-hosted fonts, SHA-pinned GitHub Actions updated by Dependabot), secret leakage, accepted clickjacking risk, and subdomain takeover.

## Signaler une faille

Merci de **ne pas ouvrir d'issue publique** pour une faille : elle serait visible de tous avant d'être corrigée.

Utilise le **signalement privé de GitHub** : onglet **Security** du dépôt, puis **Report a vulnerability**, ou directement :
<https://github.com/angele-os/net-toolkit/security/advisories/new>

Indique si possible :
- la version concernée (le hash du commit ou la date) et le navigateur utilisé ;
- les étapes pour reproduire le problème (la saisie exacte, le fichier CSV produit…) ;
- l'impact que tu envisages.

C'est un projet personnel d'étudiant, maintenu sur mon temps libre. J'essaie de répondre sous 7 jours, sans garantie. Seule la dernière version de la branche `main` est maintenue.

## Modèle de menace

### Ce que l'outil est (et n'est pas)

- **Une page web statique.** HTML, CSS et JavaScript sont exécutés entièrement dans le navigateur.
- **Aucune donnée n'est envoyée ni stockée côté serveur.** Il n'y a pas de serveur applicatif, pas de base de données, pas de compte, pas de cookie, pas de `localStorage`. La CSP l'impose techniquement : `default-src 'none'` sans `connect-src` interdit toute requête réseau depuis le JavaScript.
- **Seule exception, visible : le lien partageable.** Après un calcul, les valeurs saisies sont écrites dans l'adresse de la page, après le `#`. Ce fragment n'est **jamais envoyé au serveur** (le navigateur ne le transmet pas dans la requête HTTP ni dans l'en-tête `Referer`), mais il reste dans l'historique du navigateur et dans tout lien copié. Les noms de sous-réseaux ne doivent donc pas contenir d'information confidentielle si le lien est partagé.
- **Ce qu'on protège :** le navigateur de la personne qui utilise l'outil, l'ordinateur de la personne qui ouvre un CSV exporté, et l'intégrité du code publié.

### Risques et protections

| Risque | Applicable ? | Protection mise en place |
|---|---|---|
| Injection SQL | Non | Pas de base de données |
| XSS (injection de script) | Oui | `textContent` uniquement, CSP stricte, Trusted Types |
| Lien partageable piégé (`#…`) | Oui | Donnée non fiable : longueur max, `URLSearchParams`, mêmes validations que les champs |
| Injection CSV (formules) | Oui | Apostrophe devant `= + - @` tabulation retour chariot, guillemets |
| Saisies énormes | Oui | Limites dans les fonctions pures **et** `maxlength` |
| Caractères invisibles | Oui | Catégories Unicode Cc et Cf refusées dans les noms |
| Chaîne d'approvisionnement | Oui | 0 dépendance npm, polices auto-hébergées, actions épinglées par SHA + Dependabot |
| Fuite de secrets | Faible | Aucun secret nécessaire, jeton CI en lecture seule |
| Clickjacking | Risque accepté | Voir justification |
| Vol de sous-domaine | À la mise en ligne | Domaine vérifié, ordre de suppression DNS |

#### Injection SQL : non applicable

L'injection SQL consiste à glisser du code SQL dans une saisie pour qu'un serveur l'exécute sur sa base de données. net-toolkit n'a **ni serveur ni base de données** : aucune requête SQL n'existe, il n'y a donc rien à injecter. Si une base de données était ajoutée un jour, il faudrait utiliser des requêtes paramétrées.

#### XSS (Cross-Site Scripting)

Le risque : une saisie (par exemple un nom de sous-réseau) contenant du HTML ou du JavaScript serait interprétée par la page.

Les protections :
- **Aucun `innerHTML`.** Tout texte est inséré avec `textContent`, qui affiche les caractères tels quels. La ligne de besoin est un `<template>` HTML cloné avec `cloneNode`.
- **CSP stricte** (balise `<meta>`) : `default-src 'none'; script-src 'self'; style-src 'self'`. Aucun script ni style en ligne, aucun `onclick="…"`, pas d'`eval`.
- **Trusted Types** : `require-trusted-types-for 'script'; trusted-types 'none'`. Le navigateur refuse toute écriture de texte dans une fonction dangereuse (`innerHTML`, `eval`…), même si du code en ajoutait une par erreur plus tard. Cette directive est appliquée par les navigateurs qui la prennent en charge.
- **`base-uri 'none'`** (empêche de détourner les liens relatifs avec une balise `<base>`) et **`object-src 'none'`** (pas de plugins).
- Un test (`tests/html.test.js`) vérifie que la CSP contient ces directives et que le HTML ne contient aucun script, style ou gestionnaire d'événement en ligne.

#### Lien partageable piégé (fragment `#…`)

Le risque : le lien partageable (par exemple `#vlsm=192.168.10.0/24&nom=Admin&hotes=100`) est lu automatiquement à l'ouverture de la page. **N'importe qui peut fabriquer un tel lien** et l'envoyer à une victime par message, courriel ou QR code. Sans validation, ce lien pourrait injecter du HTML dans la page (XSS), faire planter l'outil ou le bloquer avec un fragment énorme, ou glisser des caractères invisibles et des formules dans un CSV que la victime exportera ensuite.

La protection (`js/etat.js`, testée dans `tests/etat.test.js`) : le fragment est traité **exactement comme une saisie au clavier**.
- **Longueur maximale** vérifiée avant toute lecture. Elle est calculée à partir des limites de saisie (256 besoins de 32 caractères), et le message d'erreur ne recopie pas le fragment.
- **Découpage avec `URLSearchParams`**, qui ne lève pas d'exception sur un encodage `%` invalide (contrairement à `decodeURIComponent`).
- **Validation par les mêmes fonctions et limites que les champs** : `parseCidr` (40 caractères), `erreurNom` (32 caractères, pas de caractère Cc/Cf), `erreurHotes` (1 à 10 chiffres, rien d'autre que `0-9`), 256 besoins au maximum. Un seul mode (`ip` ou `vlsm`) est accepté.
- Les valeurs validées sont placées dans les champs avec `.value`, puis le **calcul normal** est lancé : il revérifie tout (alignement du réseau, capacité) et affiche ses erreurs sous les champs.
- **Aucun plantage** : toute erreur de lecture est affichée en texte (`textContent`) au-dessus des onglets, et l'outil reste utilisable avec ses valeurs par défaut.
- Le fragment n'est jamais utilisé pour naviguer (`location = …`) ni pour charger une ressource. `history.replaceState` n'écrit qu'un fragment sur la même page.

#### Injection CSV (injection de formule)

Le risque : un nom de sous-réseau comme `=HYPERLINK("http://pirate.example";"Clique")` serait exécuté comme une formule quand le CSV exporté est ouvert dans Excel ou LibreOffice.

La protection (`js/export.js`, testée dans `tests/export.test.js`), conforme aux recommandations OWASP sur la *CSV Injection* :
- une cellule qui commence par `=`, `+`, `-`, `@`, une tabulation ou un retour chariot est **préfixée d'une apostrophe**, et le tableur l'affiche alors comme du texte ;
- une cellule qui contient `;`, `"` ou un retour à la ligne est **entourée de guillemets**, et ses `"` sont doublés. Sans ça, `a;=1+1` serait coupé en deux cellules, la seconde étant une formule ;
- la copie dans le presse-papiers applique la même protection.

Compromis accepté : un nom qui commence légitimement par `-` (par exemple `-Serveurs`) apparaît avec une apostrophe dans le tableur.

#### Saisies énormes

Le risque : coller un texte de plusieurs mégaoctets, ou demander des milliers de sous-réseaux, pour bloquer l'onglet ou remplir l'écran de messages d'erreur.

Les protections, appliquées **dans les fonctions pures** (même si l'on contourne l'interface) **et** dans le HTML (`maxlength`, pour le confort) :

| Saisie | Limite |
|---|---|
| Adresse IP ou réseau | 40 caractères |
| Nom d'un besoin | 32 caractères |
| Nombre d'hôtes | 10 chiffres (9 999 999 999) |
| Nombre de besoins | 256 (le bouton « Ajouter » se désactive avec un message) |

Autres précautions :
- la longueur est vérifiée **avant** tout traitement, et les messages d'erreur ne recopient pas un texte trop long ;
- les expressions régulières sont simples (pas de répétitions imbriquées), donc sans risque de ReDoS, un blocage dû à une expression régulière qui s'emballe ;
- un test vérifie que les `maxlength` du HTML restent égaux aux limites des fonctions pures.

#### Caractères invisibles et de contrôle

Le risque : un nom contenant des caractères Unicode invisibles trompe la personne qui lit le résultat ou le CSV. Par exemple, U+202E (*Right-to-Left Override*) inverse l'affichage de la suite du texte : c'est la technique « Trojan Source », CVE-2021-42574. D'autres exemples sont U+200B (espace sans chasse) ou les caractères de contrôle comme U+001B (échappement).

La protection (`erreurNom` dans `js/vlsm.js`) : tout nom qui contient un caractère des catégories Unicode **Cc** (contrôle) ou **Cf** (mise en forme invisible) est refusé. Le message d'erreur donne le **code** du caractère (« U+202E ») sans le recopier, pour ne pas retourner l'affichage du message lui-même.

Compromis accepté : les emojis composés avec le liant U+200D (par exemple 👩‍💻) sont refusés. Les emojis simples sont acceptés.

#### Chaîne d'approvisionnement

Le risque : du code malveillant arrive par une dépendance, un CDN ou un outil d'intégration continue compromis.

Les protections :
- **Aucune dépendance npm**, ni à l'exécution ni pour les tests (`node:test` est intégré à Node.js). `"private": true` dans `package.json` empêche une publication accidentelle sur npm.
- **Aucune ressource externe** : les polices sont auto-hébergées dans `fonts/` (licence SIL OFL 1.1), et la CSP (`'self'`) bloque tout CDN.
- **GitHub Actions épinglées par empreinte SHA complète** (avec la version en commentaire). Contrairement à une étiquette comme `v7`, un SHA ne peut pas être déplacé vers un autre code.
- **Dependabot** (`.github/dependabot.yml`) propose chaque semaine les mises à jour de ces actions, à relire avant de fusionner.
- Le workflow s'exécute avec **`permissions: contents: read`** et utilise l'évènement `pull_request` (et non `pull_request_target`) : une pull request venant d'un fork ne reçoit ni secret ni droit d'écriture.

#### Fuite de secrets

Le risque : une clé ou un mot de passe publié dans ce dépôt public, ou volé pendant l'intégration continue.

Les protections :
- l'outil **n'a besoin d'aucun secret** : pas d'API, pas de clé, pas de compte ;
- `.gitignore` exclut les fichiers `.env` ;
- dans le workflow, le jeton GitHub est en **lecture seule**, et `persist-credentials: false` évite de le laisser dans la configuration git de la machine de test ;
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
- Les erreurs de calcul réseau : ce sont des bugs à signaler dans une issue publique, pas des failles de sécurité.
