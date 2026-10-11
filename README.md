# net-toolkit

[![Tests](https://github.com/angele-os/net-toolkit/actions/workflows/tests.yml/badge.svg)](https://github.com/angele-os/net-toolkit/actions/workflows/tests.yml)
[![Déploiement](https://github.com/angele-os/net-toolkit/actions/workflows/deploy.yml/badge.svg)](https://github.com/angele-os/net-toolkit/actions/workflows/deploy.yml)

[Français](#français) · [English](#english)

## Français

Calculateur IPv4 et VLSM qui fonctionne entièrement dans le navigateur : analyser une adresse, puis découper un réseau en sous-réseaux dimensionnés selon chaque besoin.

**Démo : <https://reseau.ange-bonkoski.fr>**

HTML, CSS et JavaScript sans framework, sans dépendance npm.

### Fonctionnalités

#### Analyse d'une adresse IPv4

- Saisie en notation CIDR (`192.168.1.37/27`) ou avec un masque (`192.168.1.37 255.255.255.224`) ; les masques non contigus sont refusés.
- Adresse réseau, broadcast, masque, masque inverse (wildcard), première et dernière adresses utilisables, nombre d'hôtes utilisables et nombre total d'adresses.
- Cas particuliers pris en charge : /31 (liaison point à point, RFC 3021) et /32 (hôte unique).
- Sous-réseau suivant de même taille.
- Type d'adresse (privée RFC 1918, publique, loopback, lien local, multicast, réservée) et classe historique (A à E).
- Représentation binaire, avec les bits réseau mis en évidence, et hexadécimale.

![Capture d'écran : analyse de l'adresse 192.168.1.37/27, avec adresse réseau, masque, broadcast, plage utilisable et représentation binaire](docs/capture-ip.png)

#### Plan d'adressage VLSM

- Un réseau de départ et une liste de besoins (nom et nombre d'hôtes), jusqu'à 256 sous-réseaux.
- Pour chaque sous-réseau : adresse CIDR, masque, passerelle (première adresse utilisable), plage utilisable, broadcast et taux d'utilisation.
- Barre de répartition visuelle du réseau de départ.
- Espace restant découpé en blocs CIDR réutilisables.
- Messages d'erreur explicites : réseau de départ mal aligné (avec l'adresse correcte suggérée), plan trop grand (avec le nombre d'adresses manquantes).

![Capture d'écran : plan VLSM de 192.168.10.0/24 pour quatre besoins, avec barre de répartition, tableau des sous-réseaux et blocs libres](docs/capture-vlsm.png)

#### Export et utilisation

- Copie des résultats en un clic, prête à coller dans un tableur.
- Téléchargement CSV (séparateur `;`, compatible avec Excel en français), protégé contre l'injection de formules.
- Mise en page dédiée à l'impression (A4 paysage, résultats seuls).
- Interface en français, adaptée au mobile, conçue pour la navigation au clavier et les lecteurs d'écran.
- Aucune donnée envoyée ni stockée : pas de serveur, pas de cookie, pas de stockage local.

### Comment fonctionne l'algorithme VLSM

VLSM (*Variable Length Subnet Mask*, masque de longueur variable) attribue à chaque sous-réseau un masque adapté à sa taille, au lieu de découper le réseau en parts égales. On gaspille ainsi beaucoup moins d'adresses.

Exemple : le réseau `192.168.10.0/24` (256 adresses) d'une petite entreprise, avec quatre besoins.

1. **Taille de chaque bloc.** Un sous-réseau contient toujours une puissance de 2 d'adresses, dont deux sont réservées : l'adresse réseau et le broadcast. On retient donc la plus petite puissance de 2 supérieure ou égale à « hôtes + 2 ». Pour 100 hôtes : 102 adresses nécessaires, donc un bloc de 128, soit un /25.
2. **Vérification.** On additionne les blocs : 128 + 64 + 32 + 4 = 228 adresses, ce qui tient dans les 256 disponibles. Dans le cas contraire, l'outil indique combien d'adresses manquent.
3. **Tri du plus grand au plus petit.** Un bloc de 128 adresses doit commencer sur un multiple de 128 (c'est l'alignement). En plaçant les plus grands blocs d'abord, chaque bloc suivant tombe naturellement sur une frontière valide, sans laisser de trou.
4. **Placement.** Les blocs sont posés les uns à la suite des autres depuis le début du réseau.
5. **Espace libre.** Les adresses restantes sont découpées en blocs CIDR alignés, les plus grands possible, réutilisables pour de futurs besoins.

Résultat :

| Besoin | Hôtes demandés | Sous-réseau | Plage utilisable | Broadcast | Utilisation |
|---|---:|---|---|---|---:|
| Bureautique | 100 | 192.168.10.0/25 | .1 à .126 | .127 | 79,4 % |
| Serveurs | 50 | 192.168.10.128/26 | .129 à .190 | .191 | 80,6 % |
| Wi-Fi invités | 20 | 192.168.10.192/27 | .193 à .222 | .223 | 66,7 % |
| Lien WAN | 2 | 192.168.10.224/30 | .225 à .226 | .227 | 100 % |

Espace libre : 28 adresses, de `192.168.10.228` à `192.168.10.255`, soit les blocs `192.168.10.228/30`, `192.168.10.232/29` et `192.168.10.240/28`.

C'est ce plan qui apparaît sur la [capture du plan VLSM](docs/capture-vlsm.png) ci-dessus.

### Lancer les tests en local

Prérequis : Node.js 24 ou plus récent. Aucune dépendance à installer : les tests utilisent `node:test`, le lanceur de tests intégré à Node.js.

```sh
git clone https://github.com/angele-os/net-toolkit.git
cd net-toolkit
npm test            # lance tous les tests
npm run coverage    # idem, avec le taux de couverture du code
```

Les tests couvrent les calculs (`js/ip.js`, `js/vlsm.js`), l'export (`js/export.js`) et des règles de sécurité vérifiées automatiquement sur le HTML (CSP, absence de script en ligne) et sur les workflows (actions épinglées par SHA). Ils s'exécutent à chaque push et à chaque pull request ; le site n'est publié que s'ils réussissent.

### Sécurité

net-toolkit est une page statique : pas de serveur, pas de base de données, pas de compte, et les saisies ne quittent jamais le navigateur. Les protections mises en place (CSP stricte avec Trusted Types, insertion du texte sans interprétation HTML, protection des exports CSV, limites de saisie, aucune dépendance, publication par liste blanche) sont détaillées avec le modèle de menace dans [SECURITY.md](SECURITY.md). Pour signaler une faille, merci d'utiliser le [signalement privé de GitHub](https://github.com/angele-os/net-toolkit/security/advisories/new) plutôt qu'une issue publique.

### Feuille de route

- **Prochaine étape : générateur de configurations Cisco.** À partir d'un plan d'adressage VLSM, produire les commandes de configuration Cisco IOS correspondantes.

### Licence

Code distribué sous licence MIT : voir [LICENSE](LICENSE). Les polices Inter et Fraunces, auto-hébergées dans `fonts/`, sont distribuées sous SIL Open Font License 1.1 : voir [fonts/README.md](fonts/README.md).

---

## English

IPv4 and VLSM calculator that runs entirely in the browser: analyse an address, then split a network into subnets sized for each requirement.

**Demo: <https://reseau.ange-bonkoski.fr>** (the interface is in French; see the screenshots of the [address analysis](docs/capture-ip.png) and the [VLSM plan](docs/capture-vlsm.png)).

Plain HTML, CSS and JavaScript: no framework, no npm dependencies.

### Features

#### IPv4 address analysis

- Input in CIDR notation (`192.168.1.37/27`) or with a subnet mask (`192.168.1.37 255.255.255.224`); non-contiguous masks are rejected.
- Network address, broadcast, subnet mask, wildcard mask, first and last usable addresses, number of usable hosts and total addresses.
- Edge cases handled: /31 (point-to-point link, RFC 3021) and /32 (single host).
- Next subnet of the same size.
- Address type (private RFC 1918, public, loopback, link-local, multicast, reserved) and historical class (A to E).
- Binary representation, with network bits highlighted, and hexadecimal.

#### VLSM addressing plan

- A starting network and a list of requirements (name and number of hosts), up to 256 subnets.
- For each subnet: CIDR address, mask, gateway (first usable address), usable range, broadcast and utilisation rate.
- Visual allocation bar of the starting network.
- Remaining space split into reusable CIDR blocks.
- Clear error messages: misaligned starting network (with the correct address suggested), plan too large (with the number of missing addresses).

#### Export and usability

- One-click copy of the results, ready to paste into a spreadsheet.
- CSV download (`;` separator, compatible with French-locale Excel), protected against formula injection.
- Dedicated print layout (A4 landscape, results only).
- French interface, mobile-friendly, designed for keyboard navigation and screen readers.
- No data sent or stored: no server, no cookies, no local storage.

### How the VLSM algorithm works

VLSM (Variable Length Subnet Mask) gives each subnet a mask suited to its size instead of splitting the network into equal parts, which wastes far fewer addresses.

Example: a small company's `192.168.10.0/24` network (256 addresses) with four requirements.

1. **Block size.** A subnet always holds a power of 2 addresses, two of which are reserved: the network address and the broadcast. The tool therefore picks the smallest power of 2 greater than or equal to "hosts + 2". For 100 hosts: 102 addresses needed, so a 128-address block, i.e. a /25.
2. **Check.** The blocks add up to 128 + 64 + 32 + 4 = 228 addresses, which fits in the 256 available. Otherwise, the tool reports how many addresses are missing.
3. **Sort from largest to smallest.** A 128-address block must start on a multiple of 128 (alignment). Placing the largest blocks first guarantees that each following block lands on a valid boundary, with no gaps.
4. **Placement.** Blocks are laid out one after another from the start of the network.
5. **Free space.** The remaining addresses are split into the largest possible aligned CIDR blocks, available for future needs.

Result:

| Requirement | Requested hosts | Subnet | Usable range | Broadcast | Utilisation |
|---|---:|---|---|---|---:|
| Office | 100 | 192.168.10.0/25 | .1 to .126 | .127 | 79.4% |
| Servers | 50 | 192.168.10.128/26 | .129 to .190 | .191 | 80.6% |
| Guest Wi-Fi | 20 | 192.168.10.192/27 | .193 to .222 | .223 | 66.7% |
| WAN link | 2 | 192.168.10.224/30 | .225 to .226 | .227 | 100% |

Free space: 28 addresses, from `192.168.10.228` to `192.168.10.255`, i.e. blocks `192.168.10.228/30`, `192.168.10.232/29` and `192.168.10.240/28`.

This is the plan shown in the [VLSM screenshot](docs/capture-vlsm.png).

### Running the tests locally

Requirement: Node.js 24 or later. Nothing to install: the tests use `node:test`, the test runner built into Node.js.

```sh
git clone https://github.com/angele-os/net-toolkit.git
cd net-toolkit
npm test            # run all tests
npm run coverage    # same, with code coverage
```

The tests cover the calculations (`js/ip.js`, `js/vlsm.js`), the export (`js/export.js`) and security rules checked automatically against the HTML (CSP, no inline script) and the workflows (SHA-pinned actions). They run on every push and pull request; the site is only deployed when they pass.

### Security

net-toolkit is a static page: no server, no database, no account, and input never leaves the browser. The safeguards (strict CSP with Trusted Types, text inserted without HTML interpretation, CSV export protection, input limits, zero dependencies, allow-listed deployment) are documented together with the threat model in [SECURITY.md](SECURITY.md). To report a vulnerability, please use [GitHub private vulnerability reporting](https://github.com/angele-os/net-toolkit/security/advisories/new) rather than a public issue.

### Roadmap

- **Next step: Cisco configuration generator.** Produce the matching Cisco IOS configuration commands from a VLSM addressing plan.

### License

Code released under the MIT License: see [LICENSE](LICENSE). The Inter and Fraunces fonts, self-hosted in `fonts/`, are released under the SIL Open Font License 1.1: see [fonts/README.md](fonts/README.md).
