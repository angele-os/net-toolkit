// Interface de net-toolkit : relie la page (index.html) aux calculs (ip.js, vlsm.js).
// Ce fichier ne fait AUCUN calcul réseau : il lit les champs, appelle les fonctions pures,
// puis affiche les résultats.
// Sécurité : jamais d'innerHTML. Tout texte (surtout ce que l'utilisateur a saisi)
// est inséré avec textContent, qui affiche le texte tel quel sans l'interpréter comme du HTML.
import { parseCidr, ipToString, analyze } from './ip.js';
import { planVlsm, erreurNom, erreurHotes, BESOINS_MAX } from './vlsm.js';
import { versTexteTabule, versCsv } from './export.js';

/* ==================== Petits utilitaires ==================== */

// Libellés français des types renvoyés par analyze() : version courte (chiffres clés) et longue (tableau).
const TYPES = {
  private: { court: 'Privée', long: 'Privée (RFC 1918)' },
  public: { court: 'Publique', long: 'Publique' },
  loopback: { court: 'Loopback', long: 'Loopback (127.0.0.0/8)' },
  'link-local': { court: 'Link-local', long: 'Link-local / APIPA (169.254.0.0/16)' },
  multicast: { court: 'Multicast', long: 'Multicast (224.0.0.0/4)' },
  reserved: { court: 'Réservée', long: 'Réservée' },
};

// Nombre à la française pour l'affichage : 16777214 → « 16 777 214 ».
const nombre = (n) => n.toLocaleString('fr-FR');

// Nombre décimal pour le CSV : virgule décimale (Excel français), sans séparateur de milliers.
const decimalCsv = (n) => String(n).replace('.', ',');

// Met une majuscule au début d'un message (« le nom est vide. » → « Le nom est vide. »).
const majuscule = (texte) => texte.charAt(0).toUpperCase() + texte.slice(1);

// Crée un élément avec une classe et un texte (toujours via textContent).
function creer(balise, classe, texte) {
  const element = document.createElement(balise);
  if (classe) element.className = classe;
  if (texte !== undefined) element.textContent = texte;
  return element;
}

// Zone role="status" : ce qu'on y écrit est lu par les lecteurs d'écran.
const zoneAnnonce = document.getElementById('annonce');
function annoncer(message) {
  // On vide puis on réécrit un peu plus tard : sinon un même message (« Copié » deux fois) ne serait pas relu.
  zoneAnnonce.textContent = '';
  setTimeout(() => {
    zoneAnnonce.textContent = message;
  }, 60);
}

/* ==================== Erreurs sous les champs ==================== */
// Chaque champ a un <p class="field-error" id="<id du champ>-error">, relié par aria-describedby.

function afficherErreur(champ, message) {
  document.getElementById(`${champ.id}-error`).textContent = message;
  // aria-invalid : le lecteur d'écran annonce « non valide » sur ce champ.
  champ.setAttribute('aria-invalid', 'true');
}

function effacerErreur(champ) {
  document.getElementById(`${champ.id}-error`).textContent = '';
  champ.removeAttribute('aria-invalid');
}

// Dès qu'on corrige un champ, son erreur disparaît.
function effacerErreurEnTapant(champ) {
  champ.addEventListener('input', () => effacerErreur(champ));
}

/* ==================== Onglets accessibles ==================== */
// Modèle « tabs » de l'ARIA : un seul onglet atteignable avec Tab (tabindex 0),
// on passe d'un onglet à l'autre avec les flèches gauche/droite (et Début/Fin).

const onglets = [...document.querySelectorAll('[role="tab"]')];

function activerOnglet(onglet, donnerFocus) {
  for (const o of onglets) {
    const actif = o === onglet;
    o.setAttribute('aria-selected', String(actif));
    o.tabIndex = actif ? 0 : -1;
    // Le panneau lié (aria-controls) est affiché ou caché.
    document.getElementById(o.getAttribute('aria-controls')).hidden = !actif;
  }
  if (donnerFocus) onglet.focus();
}

onglets.forEach((onglet, i) => {
  onglet.addEventListener('click', () => activerOnglet(onglet, false));
  onglet.addEventListener('keydown', (event) => {
    const n = onglets.length;
    let cible = null;
    // Onglet suivant (on revient au premier après le dernier : modulo n).
    if (event.key === 'ArrowRight') cible = onglets[(i + 1) % n];
    // Onglet précédent (+ n pour ne jamais avoir d'indice négatif).
    if (event.key === 'ArrowLeft') cible = onglets[(i - 1 + n) % n];
    if (event.key === 'Home') cible = onglets[0];
    if (event.key === 'End') cible = onglets[n - 1];
    if (cible) {
      event.preventDefault();
      activerOnglet(cible, true);
    }
  });
});

/* ==================== Affichages communs ==================== */

// Chiffres clés : liste de [libellé, valeur] → <div class="stat"><dt>…</dt><dd>…</dd></div>
function afficherStats(conteneur, stats) {
  conteneur.replaceChildren(
    ...stats.map(([libelle, valeur]) => {
      const bloc = creer('div', 'stat');
      bloc.append(creer('dt', 'stat__label', libelle), creer('dd', 'stat__value', valeur));
      return bloc;
    }),
  );
}

// IP en binaire : les bits réseau (les « prefixe » premiers) sont mis en évidence.
function afficherBinaire(conteneur, binaire, prefixe) {
  conteneur.replaceChildren();
  binaire.split('.').forEach((octet, i) => {
    const groupe = creer('span', 'octet');
    // Position du premier bit de cet octet dans les 32 bits : 0, 8, 16 ou 24.
    const debut = i * 8;
    // Nombre de bits réseau dans cet octet, borné entre 0 et 8. Ex. /27, 4e octet : 27 − 24 = 3.
    const bitsReseau = Math.min(8, Math.max(0, prefixe - debut));
    if (bitsReseau > 0) groupe.append(creer('span', 'bits-reseau', octet.slice(0, bitsReseau)));
    if (bitsReseau < 8) groupe.append(creer('span', 'bits-hote', octet.slice(bitsReseau)));
    conteneur.append(groupe);
    // Un espace entre les octets (pas après le dernier).
    if (i < 3) conteneur.append(' ');
  });
}

/* ==================== Export : copier et CSV ==================== */
// Après chaque calcul, on garde ici les données à exporter : { fichier, entetes, lignes }.
// La mise en forme (et la protection contre l'injection CSV) est dans export.js, testé à part.
const exportsDisponibles = { ip: null, vlsm: null };

function telechargerCsv(nomFichier, contenu) {
  // \uFEFF (BOM, écrit avec son code pour rester visible dans le code) : indique à Excel que le fichier est en UTF-8, pour que les accents s'affichent bien.
  const blob = new Blob(['\uFEFF', contenu], { type: 'text/csv;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const lien = creer('a');
  lien.href = url;
  lien.download = nomFichier;
  document.body.append(lien);
  lien.click();
  lien.remove();
  // On libère la mémoire un peu après le début du téléchargement.
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

const minuteursCopie = new Map();

async function copier(bouton, texte) {
  try {
    await navigator.clipboard.writeText(texte);
  } catch {
    // Presse-papiers refusé (page non sécurisée, permission refusée…).
    annoncer('Copie impossible : le navigateur a refusé l’accès au presse-papiers.');
    return;
  }
  // L'icône devient une coche (voir .is-copied dans style.css) pendant 2 secondes.
  bouton.classList.add('is-copied');
  annoncer('Copié');
  clearTimeout(minuteursCopie.get(bouton));
  minuteursCopie.set(bouton, setTimeout(() => bouton.classList.remove('is-copied'), 2000));
}

for (const bouton of document.querySelectorAll('.btn-copy')) {
  bouton.addEventListener('click', () => {
    const donnees = exportsDisponibles[bouton.dataset.export];
    if (donnees) copier(bouton, versTexteTabule(donnees));
  });
}

for (const bouton of document.querySelectorAll('.btn-csv')) {
  bouton.addEventListener('click', () => {
    const donnees = exportsDisponibles[bouton.dataset.export];
    if (donnees) {
      telechargerCsv(donnees.fichier, versCsv(donnees));
      annoncer(`Téléchargement de ${donnees.fichier}`);
    }
  });
}

/* ==================== Onglet 1 : analyser une IP ==================== */

const formIp = document.getElementById('form-ip');
const champIp = document.getElementById('ip-input');
const resultatIp = document.getElementById('result-ip');
effacerErreurEnTapant(champIp);

formIp.addEventListener('submit', (event) => {
  // Empêche le rechargement de la page : tout se passe en JavaScript.
  event.preventDefault();
  effacerErreur(champIp);

  let ip;
  let prefix;
  try {
    // ip.js lit le texte et lève une erreur claire s'il est invalide.
    ({ ip, prefix } = parseCidr(champIp.value));
  } catch (erreur) {
    afficherErreur(champIp, erreur.message);
    resultatIp.hidden = true;
    champIp.focus();
    return;
  }

  const r = analyze(ip, prefix);

  afficherStats(document.getElementById('ip-stats'), [
    ['Hôtes utilisables', nombre(r.hosts)],
    ['Préfixe', `/${prefix}`],
    ['Type', TYPES[r.type].court],
  ]);

  afficherBinaire(document.getElementById('ip-binary'), r.binary, prefix);
  document.getElementById('ip-legend-reseau').textContent = `Partie réseau : ${prefix} bits`;
  document.getElementById('ip-legend-hote').textContent = `Partie hôte : ${32 - prefix} bits`;

  // Adresse saisie, réécrite proprement (« 192.168.1.37 255.255.255.224 » → « 192.168.1.37/27 »).
  const adresse = `${ipToString(ip)}/${prefix}`;
  document.getElementById('ip-resume').textContent = adresse;

  // [libellé, valeur affichée, valeur exportée, en police mono ?]
  const lignes = [
    ['Adresse IP', adresse, null, true],
    ['Adresse réseau', `${r.network}/${prefix}`, null, true],
    ['Masque', r.mask, null, true],
    ['Wildcard', r.wildcard, null, true],
    ['Broadcast', r.broadcast, null, true],
    ['Première IP utilisable', r.firstHost, null, true],
    ['Dernière IP utilisable', r.lastHost, null, true],
    ['Hôtes utilisables', nombre(r.hosts), String(r.hosts), false],
    ['Adresses au total', nombre(r.totalAddresses), String(r.totalAddresses), false],
    ['Sous-réseau suivant (même taille)', r.nextSubnet ?? 'Aucun : fin de l’espace IPv4', null, r.nextSubnet !== null],
    ['Type', TYPES[r.type].long, null, false],
    ['Classe', `${r.historicalClass} (historique, avant CIDR)`, null, false],
    ['IP en hexadécimal', r.hex, null, true],
  ];

  document.getElementById('ip-table').replaceChildren(
    ...lignes.map(([libelle, valeur, , mono]) => {
      const tr = creer('tr');
      const th = creer('th', '', libelle);
      th.scope = 'row';
      tr.append(th, creer('td', mono ? 'mono' : 'num', valeur));
      return tr;
    }),
  );

  exportsDisponibles.ip = {
    fichier: `analyse-${r.network}-${prefix}.csv`,
    entetes: ['Champ', 'Valeur'],
    lignes: [
      ...lignes.map(([libelle, valeur, valeurExport]) => [libelle, valeurExport ?? valeur]),
      ['IP en binaire', r.binary],
    ],
  };

  resultatIp.hidden = false;
  annoncer(`Résultat affiché : réseau ${r.network}/${prefix}, ${nombre(r.hosts)} hôtes utilisables.`);
});

/* ==================== Onglet 2 : plan VLSM ==================== */

const formVlsm = document.getElementById('form-vlsm');
const champReseau = document.getElementById('vlsm-reseau');
const listeBesoins = document.getElementById('besoins-liste');
const modeleBesoin = document.getElementById('modele-besoin');
const boutonAjouter = document.getElementById('btn-ajouter');
const resultatVlsm = document.getElementById('result-vlsm');
effacerErreurEnTapant(champReseau);

// Compteur pour donner des id uniques aux champs (« besoin-3-nom »), même après des suppressions.
let compteurBesoins = 0;

function ajouterBesoin(nom = '', hotes = '') {
  compteurBesoins++;
  // Copie du <template> défini dans index.html.
  const ligne = modeleBesoin.content.firstElementChild.cloneNode(true);

  const champs = [
    [ligne.querySelector('.js-nom'), `besoin-${compteurBesoins}-nom`, nom],
    [ligne.querySelector('.js-hotes'), `besoin-${compteurBesoins}-hotes`, hotes],
  ];
  for (const [champ, id, valeur] of champs) {
    const bloc = champ.closest('.field');
    champ.id = id;
    champ.value = String(valeur);
    // Relie le <label> au champ (for = id) et la zone d'erreur au champ (aria-describedby).
    bloc.querySelector('label').htmlFor = id;
    bloc.querySelector('.field-error').id = `${id}-error`;
    champ.setAttribute('aria-describedby', `${id}-error`);
    effacerErreurEnTapant(champ);
  }

  ligne.querySelector('.js-supprimer').addEventListener('click', () => supprimerBesoin(ligne));
  listeBesoins.append(ligne);
  renumeroterBesoins();
  return ligne;
}

function supprimerBesoin(ligne) {
  // Le focus ira sur la ligne suivante (ou précédente) pour ne pas « perdre » l'utilisateur clavier.
  const voisine = ligne.nextElementSibling ?? ligne.previousElementSibling;
  ligne.remove();
  renumeroterBesoins();
  (voisine?.querySelector('.js-nom') ?? boutonAjouter).focus();
  annoncer('Ligne supprimée.');
}

// Message affiché sous « Ajouter un besoin » quand la limite est atteinte (relié par aria-describedby).
const messageLimite = document.getElementById('besoins-limite');
const TEXTE_LIMITE = `Limite de ${BESOINS_MAX} besoins atteinte : supprime une ligne pour en ajouter une autre.`;

// Met à jour « Nom du besoin 2 », « Supprimer le besoin 2 »… interdit de supprimer la dernière ligne
// et désactive « Ajouter » quand la limite BESOINS_MAX (définie dans vlsm.js) est atteinte.
function renumeroterBesoins() {
  const lignes = [...listeBesoins.children];
  lignes.forEach((ligne, i) => {
    for (const span of ligne.querySelectorAll('.besoin__num')) span.textContent = ` du besoin ${i + 1}`;
    const bouton = ligne.querySelector('.js-supprimer');
    bouton.setAttribute('aria-label', `Supprimer le besoin ${i + 1}`);
    bouton.disabled = lignes.length === 1;
  });
  const plein = lignes.length >= BESOINS_MAX;
  boutonAjouter.disabled = plein;
  messageLimite.textContent = plein ? TEXTE_LIMITE : '';
}

boutonAjouter.addEventListener('click', () => {
  // Sécurité en plus du bouton désactivé : on ne dépasse jamais la limite.
  if (listeBesoins.children.length >= BESOINS_MAX) return;
  ajouterBesoin().querySelector('.js-nom').focus();
  // Le bouton vient d'être désactivé : on l'annonce, sinon un utilisateur de lecteur d'écran ne le saurait pas.
  if (boutonAjouter.disabled) annoncer(TEXTE_LIMITE);
});

// Plan d'exemple (réseau d'une petite entreprise) : lignes de départ, et contenu du bouton
// « Exemple : 100 / 50 / 20 / 2 hôtes ».
const EXEMPLE_PLAN = {
  reseau: '192.168.10.0/24',
  besoins: [
    { nom: 'Bureautique', hotes: 100 },
    { nom: 'Serveurs', hotes: 50 },
    { nom: 'Wi-Fi invités', hotes: 20 },
    { nom: 'Lien WAN', hotes: 2 },
  ],
};

// Remplace toutes les lignes de besoins par celles fournies.
function remplacerBesoins(besoins) {
  listeBesoins.replaceChildren();
  for (const { nom, hotes } of besoins) ajouterBesoin(nom, hotes);
}

// Lignes de départ (modifiables).
remplacerBesoins(EXEMPLE_PLAN.besoins);

// Vérifie chaque ligne pour afficher l'erreur sous le bon champ.
// Les règles viennent de vlsm.js (erreurNom, erreurHotes) : un seul endroit les définit,
// et planVlsm() les applique de toute façon. Ici, c'est pour placer le message au bon endroit.
function lireBesoins(champsEnErreur) {
  return [...listeBesoins.children].map((ligne) => {
    const champNom = ligne.querySelector('.js-nom');
    const champHotes = ligne.querySelector('.js-hotes');
    const texteHotes = champHotes.value.trim();

    const erreurDuNom = erreurNom(champNom.value);
    if (erreurDuNom) {
      afficherErreur(champNom, majuscule(erreurDuNom));
      champsEnErreur.push(champNom);
    }
    let message = '';
    if (texteHotes === '') message = 'Indique le nombre d’hôtes.';
    // Que des chiffres : refuse « 2.5 », « -3 », « dix »…
    else if (!/^\d+$/.test(texteHotes)) message = 'Nombre entier attendu (ex. 50).';
    else message = majuscule(erreurHotes(Number(texteHotes)) ?? '');
    if (message) {
      afficherErreur(champHotes, message);
      champsEnErreur.push(champHotes);
    }
    return { nom: champNom.value, hotes: Number(texteHotes) };
  });
}

formVlsm.addEventListener('submit', (event) => {
  event.preventDefault();

  // On repart de zéro : plus aucune erreur affichée.
  for (const champ of formVlsm.querySelectorAll('.input')) effacerErreur(champ);
  const champsEnErreur = [];

  // 1. Le réseau de départ est-il lisible ?
  try {
    parseCidr(champReseau.value);
  } catch (erreur) {
    afficherErreur(champReseau, erreur.message);
    champsEnErreur.push(champReseau);
  }

  // 2. Les lignes de besoins sont-elles remplies correctement ?
  const besoins = lireBesoins(champsEnErreur);

  if (champsEnErreur.length > 0) {
    resultatVlsm.hidden = true;
    // Le focus va sur le premier champ en erreur : le lecteur d'écran lit le champ et son erreur.
    champsEnErreur[0].focus();
    return;
  }

  // 3. Calcul. Les erreurs restantes (réseau mal aligné, plan trop grand) concernent le réseau de départ.
  let plan;
  try {
    plan = planVlsm(champReseau.value, besoins);
  } catch (erreur) {
    afficherErreur(champReseau, erreur.message);
    resultatVlsm.hidden = true;
    champReseau.focus();
    return;
  }

  // Taille du réseau de départ : 2^(bits hôte).
  const tailleReseau = 2 ** (32 - parseCidr(plan.network).prefix);
  // Adresses non attribuées (0 si le plan remplit tout le réseau).
  const libres = plan.free ? plan.free.addresses : 0;
  // Part du réseau occupée par les sous-réseaux, en %, arrondie à 0,1.
  const occupation = Math.round(((tailleReseau - libres) / tailleReseau) * 1000) / 10;

  afficherStats(document.getElementById('vlsm-stats'), [
    ['Sous-réseaux', nombre(plan.subnets.length)],
    ['Espace utilisé', `${nombre(occupation)} %`],
    ['Adresses libres', nombre(libres)],
  ]);

  // Tableau : une ligne par sous-réseau. data-label sert aux cartes mobiles (voir style.css).
  const entetes = [...formVlsm.closest('.tabpanel').querySelectorAll('thead th')].map((th) => th.textContent);
  document.getElementById('vlsm-table').replaceChildren(
    ...plan.subnets.map((s) => {
      const tr = creer('tr');
      tr.setAttribute('role', 'row');

      const th = creer('th', '', s.name);
      th.scope = 'row';
      th.setAttribute('role', 'rowheader');
      tr.append(th);

      // Un seul <span> autour de la plage : en carte mobile, la cellule est une grille à 2 colonnes
      // (libellé | valeur) et chaque enfant direct deviendrait sinon une case séparée.
      const plage = creer('td', 'mono');
      const contenuPlage = creer('span');
      contenuPlage.append(creer('span', 'plage__ip', s.firstHost), ' – ', creer('span', 'plage__ip', s.lastHost));
      plage.append(contenuPlage);

      const cellules = [
        creer('td', 'num', nombre(s.requestedHosts)),
        creer('td', 'mono', s.cidr),
        creer('td', 'mono', s.mask),
        creer('td', 'mono', s.gateway),
        plage,
        creer('td', 'mono', s.broadcast),
        creer('td', 'num', `${nombre(s.usage)} % (${s.requestedHosts}/${s.usableHosts})`),
      ];
      cellules.forEach((td, i) => {
        td.setAttribute('role', 'cell');
        // i + 1 : la colonne 0 est le nom (th).
        td.dataset.label = entetes[i + 1];
        tr.append(td);
      });
      return tr;
    }),
  );

  // Espace libre.
  const texteLibre = document.getElementById('vlsm-libre');
  const listeBlocs = document.getElementById('vlsm-blocs');
  if (plan.free) {
    texteLibre.textContent = `De ${plan.free.start} à ${plan.free.end} : ${nombre(plan.free.addresses)} adresses. Blocs réutilisables :`;
    listeBlocs.replaceChildren(...plan.free.blocks.map((bloc) => creer('li', '', bloc)));
  } else {
    texteLibre.textContent = 'Aucun : le plan occupe tout le réseau.';
    listeBlocs.replaceChildren();
  }

  exportsDisponibles.vlsm = {
    // « / » est interdit dans un nom de fichier : 192.168.10.0/24 → 192.168.10.0-24
    fichier: `plan-vlsm-${plan.network.replace('/', '-')}.csv`,
    entetes: ['Nom', 'Hôtes demandés', 'Sous-réseau', 'Masque', 'Passerelle', 'Première IP', 'Dernière IP', 'Broadcast', 'Hôtes utilisables', 'Utilisation (%)'],
    lignes: plan.subnets.map((s) => [
      s.name,
      String(s.requestedHosts),
      s.cidr,
      s.mask,
      s.gateway,
      s.firstHost,
      s.lastHost,
      s.broadcast,
      String(s.usableHosts),
      decimalCsv(s.usage),
    ]),
  };

  document.getElementById('vlsm-resume').textContent = `Réseau ${plan.network}`;
  afficherBarre(plan, tailleReseau);

  resultatVlsm.hidden = false;
  annoncer(`Plan calculé : ${plan.subnets.length} sous-réseaux, ${nombre(libres)} adresses libres.`);
});

/* ==================== Barre de répartition (SVG) ==================== */

const SVG_NS = 'http://www.w3.org/2000/svg';
// Nombre de teintes de violet qui se succèdent (classes .seg-0 à .seg-3 dans style.css).
const NB_TEINTES = 4;

// Pourcentage lisible : 12.5 → « 12,5 % » ; un tout petit bloc → « < 0,1 % » plutôt que « 0 % ».
function pourcentLisible(part) {
  if (part > 0 && part < 0.1) return '< 0,1 %';
  return `${nombre(Math.round(part * 10) / 10)} %`;
}

// Un rectangle SVG de la barre : position et largeur en % du réseau de départ.
// setAttribute sur un élément SVG : ce sont des attributs, pas du style en ligne (permis par la CSP).
function segment(debut, largeur, classe) {
  const rect = document.createElementNS(SVG_NS, 'rect');
  rect.setAttribute('x', `${debut}%`);
  rect.setAttribute('width', `${largeur}%`);
  rect.setAttribute('height', '100%');
  rect.setAttribute('class', classe);
  return rect;
}

// Une entrée de légende : pastille de couleur + texte.
function entreeLegende(classe, texte) {
  const li = creer('li');
  li.append(creer('span', `pastille ${classe}`), creer('span', '', texte));
  return li;
}

function afficherBarre(plan, tailleReseau) {
  const rectangles = [];
  const legende = [];
  const phrases = [];
  // Position du prochain bloc, en % depuis la gauche de la barre.
  let position = 0;

  plan.subnets.forEach((s, i) => {
    // Taille du sous-réseau : 2^(bits hôte).
    const taille = 2 ** (32 - s.prefix);
    // Part du réseau de départ, en %.
    const part = (taille / tailleReseau) * 100;
    // Les teintes tournent : 0, 1, 2, 3, 0, 1… (reste de la division par NB_TEINTES).
    const classe = `seg-${i % NB_TEINTES}`;
    rectangles.push(segment(position, part, `segment ${classe}`));
    legende.push(entreeLegende(classe, `${s.name} · ${s.cidr} · ${pourcentLisible(part)}`));
    phrases.push(`${s.name} ${pourcentLisible(part)} (${s.cidr}, ${nombre(taille)} adresses)`);
    // Le bloc suivant commence juste après celui-ci.
    position += part;
  });

  if (plan.free) {
    // L'espace libre occupe tout le reste de la barre, hachuré.
    const part = (plan.free.addresses / tailleReseau) * 100;
    rectangles.push(segment(position, part, 'segment segment--libre'));
    legende.push(entreeLegende('pastille--libre', `Espace libre · ${pourcentLisible(part)}`));
    phrases.push(`espace libre ${pourcentLisible(part)} (${nombre(plan.free.addresses)} adresses)`);
  }

  document.getElementById('vlsm-barre-segments').replaceChildren(...rectangles);
  document.getElementById('vlsm-barre-legende').replaceChildren(...legende);
  document.getElementById('vlsm-barre-desc').textContent =
    `Répartition de ${plan.network}, de gauche à droite : ${phrases.join(' ; ')}. Le détail est dans le tableau.`;
}

/* ==================== Exemples rapides ==================== */

for (const bouton of document.querySelectorAll('.js-exemple-ip')) {
  bouton.addEventListener('click', () => {
    effacerErreur(champIp);
    // data-adresse vient de notre propre HTML ; on l'écrit dans .value (jamais en HTML).
    champIp.value = bouton.dataset.adresse;
    // requestSubmit déclenche le même « submit » que le bouton Calculer : même chemin, mêmes vérifications.
    formIp.requestSubmit();
  });
}

document.getElementById('exemple-vlsm').addEventListener('click', () => {
  champReseau.value = EXEMPLE_PLAN.reseau;
  remplacerBesoins(EXEMPLE_PLAN.besoins);
  formVlsm.requestSubmit();
});
