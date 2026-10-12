// Interface de net-toolkit : relie la page (index.html) aux calculs (ip.js, vlsm.js, cisco.js).
// Ce fichier ne fait AUCUN calcul réseau : il lit les champs, appelle les fonctions pures,
// puis affiche les résultats.
// Sécurité : jamais d'innerHTML. Tout texte (surtout ce que l'utilisateur a saisi)
// est inséré avec textContent, qui affiche le texte tel quel sans l'interpréter comme du HTML.
import { parseCidr, ipToString, analyze } from './ip.js';
import { planVlsm, erreurNom, erreurHotes, BESOINS_MAX } from './vlsm.js';
import { versTexteTabule, versCsv } from './export.js';
import {
  genererConfigurations,
  depuisPlanVlsm,
  propositionsPourPlan,
  ErreurSaisie,
  DEFAUTS,
  VLANS_MAX,
} from './cisco.js';

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

// Lance le téléchargement d'un fichier fabriqué dans la page (un Blob) : rien n'est envoyé à un serveur.
function telecharger(nomFichier, blob) {
  // Adresse temporaire, valable seulement dans cette page, qui pointe vers le Blob.
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

function telechargerCsv(nomFichier, contenu) {
  // \uFEFF (BOM, écrit avec son code pour rester visible dans le code) : indique à Excel que le fichier est en UTF-8, pour que les accents s'affichent bien.
  const blob = new Blob(['\uFEFF', contenu], { type: 'text/csv;charset=utf-8' });
  telecharger(nomFichier, blob);
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

// [data-export] : les boutons des tableaux (onglets 1 et 2). Ceux des configurations Cisco ont data-config.
for (const bouton of document.querySelectorAll('.btn-copy[data-export]')) {
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

// Dernier plan calculé avec succès : c'est lui que « Envoyer vers le générateur Cisco » transmet.
let dernierPlan = null;

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

  dernierPlan = plan;
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

/* ==================== Onglet 3 : générateur Cisco ==================== */
// Chemin d'une donnée : plan VLSM → propositionsPourPlan() (valeurs de départ des champs)
// → champs modifiables → entrée de genererConfigurations() → deux textes de configuration.
// Comme pour le VLSM, ce fichier ne vérifie que la forme des champs (vide ? nombre ?) pour placer
// les messages ; les vraies règles sont dans cisco.js, qui revérifie tout.

const ongletVlsm = document.getElementById('tab-vlsm');
const ongletCisco = document.getElementById('tab-cisco');
const zoneVide = document.getElementById('cisco-vide');
const formCisco = document.getElementById('form-cisco');
const listeVlans = document.getElementById('cisco-vlans');
const modeleVlan = document.getElementById('modele-vlan');
const resultatCisco = document.getElementById('result-cisco');
const erreurCisco = document.getElementById('cisco-erreur');

// Plan affiché dans le générateur (le dernier envoyé depuis l'onglet VLSM).
let planCisco = null;
// Configurations affichées, pour Copier et Télécharger : { switch: { texte, fichier }, routeur: { … } }.
let configsCisco = null;

// Champs des réglages, rangés par le chemin de leur donnée dans l'entrée de genererConfigurations().
// C'est le même chemin que erreur.champ quand cisco.js refuse une valeur : on retrouve ainsi le champ fautif.
const champsReglages = Object.fromEntries(
  Object.entries({
    'switch.hostname': 'cisco-hostname-switch',
    'routeur.hostname': 'cisco-hostname-routeur',
    'switch.trunk': 'cisco-trunk',
    domaine: 'cisco-domaine',
    'vlanNatif.id': 'cisco-natif-id',
    'vlanNatif.nom': 'cisco-natif-nom',
    'management.id': 'cisco-mgmt-id',
    'management.nom': 'cisco-mgmt-nom',
    'management.reseau': 'cisco-mgmt-reseau',
    'portSecurity.maximum': 'cisco-ps-max',
    'portSecurity.violation': 'cisco-ps-violation',
    'portSecurity.sticky': 'cisco-ps-sticky',
    dns: 'cisco-dns',
    banniere: 'cisco-banniere',
  }).map(([chemin, id]) => [chemin, document.getElementById(id)]),
);

// Valeurs de départ des réglages : celles qui ont une valeur par défaut dans cisco.js la reprennent (DEFAUTS).
const REGLAGES_DEPART = {
  'switch.hostname': 'SW-SIEGE',
  'routeur.hostname': 'R-SIEGE',
  'switch.trunk': DEFAUTS.trunk,
  domaine: DEFAUTS.domaine,
  'vlanNatif.id': String(DEFAUTS.vlanNatif.id),
  'vlanNatif.nom': DEFAUTS.vlanNatif.nom,
  'management.nom': DEFAUTS.nomManagement,
  'portSecurity.maximum': String(DEFAUTS.portSecurity.maximum),
  'portSecurity.violation': DEFAUTS.portSecurity.violation,
  dns: '1.1.1.1',
  banniere: DEFAUTS.banniere,
};
for (const [chemin, valeur] of Object.entries(REGLAGES_DEPART)) champsReglages[chemin].value = valeur;
champsReglages['portSecurity.sticky'].checked = DEFAUTS.portSecurity.sticky;
for (const champ of Object.values(champsReglages)) effacerErreurEnTapant(champ);

// Relie un champ à son <label> (for = id) et à sa zone d'erreur (aria-describedby), comme dans le VLSM.
function relier(champ, id, label, zoneErreur) {
  champ.id = id;
  label.htmlFor = id;
  zoneErreur.id = `${id}-error`;
  champ.setAttribute('aria-describedby', `${id}-error`);
  effacerErreurEnTapant(champ);
}

// Crée la ligne d'un sous-réseau du plan : titre, case « Créer un VLAN », numéro, nom et ports.
function creerLigneVlan(sousReseau, proposition, i) {
  const ligne = modeleVlan.content.firstElementChild.cloneNode(true);
  // Le nom du sous-réseau a été saisi dans l'onglet VLSM : textContent, jamais innerHTML.
  ligne.querySelector('.js-titre').textContent = sousReseau.name;
  ligne.querySelector('.js-info').textContent = `${sousReseau.cidr} · passerelle ${sousReseau.gateway}`;
  // Pour les lecteurs d'écran : « Numéro pour Serveurs » plutôt que trois « Numéro » identiques.
  for (const span of ligne.querySelectorAll('.js-pour')) span.textContent = ` pour ${sousReseau.name}`;

  const caseCreer = ligne.querySelector('.js-creer');
  relier(caseCreer, `cisco-vlan-${i}-creer`, ligne.querySelector('.option label'), ligne.querySelector('.vlan__tete .field-error'));

  const champs = [
    [ligne.querySelector('.js-vlan-id'), 'id', String(proposition.id)],
    [ligne.querySelector('.js-vlan-nom'), 'nom', proposition.nom],
    [ligne.querySelector('.js-vlan-ports'), 'ports', proposition.ports],
  ];
  for (const [champ, suffixe, valeur] of champs) {
    const bloc = champ.closest('.field');
    relier(champ, `cisco-vlan-${i}-${suffixe}`, bloc.querySelector('label'), bloc.querySelector('.field-error'));
    champ.value = valeur;
  }

  // Case décochée : les champs de la ligne sont désactivés (et ignorés à la génération).
  function appliquerCase() {
    ligne.classList.toggle('is-off', !caseCreer.checked);
    for (const [champ] of champs) champ.disabled = !caseCreer.checked;
  }
  caseCreer.checked = proposition.creer;
  appliquerCase();
  caseCreer.addEventListener('change', () => {
    appliquerCase();
    // Un champ désactivé n'est plus vérifié : son ancienne erreur n'a plus de sens.
    // (Ici la ligne est dans la page : effacerErreur() trouve sa zone d'erreur par son id.)
    if (!caseCreer.checked) for (const [champ] of champs) effacerErreur(champ);
  });
  return ligne;
}

// Remplit le générateur avec un plan VLSM. Les réglages déjà saisis (hostnames, DNS…) sont gardés ;
// les lignes de VLAN et le management, qui dépendent du plan, sont reproposés.
function remplirGenerateur(plan) {
  planCisco = plan;
  const propositions = propositionsPourPlan(plan);
  listeVlans.replaceChildren(...plan.subnets.map((s, i) => creerLigneVlan(s, propositions.vlans[i], i)));
  champsReglages['management.id'].value = String(propositions.management.id);
  champsReglages['management.reseau'].value = propositions.management.reseau;
  for (const champ of Object.values(champsReglages)) effacerErreur(champ);
  erreurCisco.textContent = '';

  const n = plan.subnets.length;
  document.getElementById('cisco-plan').textContent = `Plan ${plan.network} · ${n} sous-réseau${n > 1 ? 'x' : ''}`;
  zoneVide.hidden = true;
  formCisco.hidden = false;
  resultatCisco.hidden = true;
}

document.getElementById('btn-envoyer-cisco').addEventListener('click', () => {
  if (!dernierPlan) return;
  remplirGenerateur(dernierPlan);
  activerOnglet(ongletCisco, true);
  annoncer(`Générateur Cisco ouvert : ${dernierPlan.subnets.length} sous-réseaux préremplis.`);
});

document.getElementById('btn-aller-vlsm').addEventListener('click', () => activerOnglet(ongletVlsm, true));

/* ----- Lecture des champs ----- */

// Lit un texte, sans les espaces autour. Vide : erreur sous le champ.
function lireTexte(champ, champsEnErreur) {
  const texte = champ.value.trim();
  if (texte === '') {
    afficherErreur(champ, 'Ce champ est obligatoire.');
    champsEnErreur.push(champ);
  }
  return texte;
}

// Lit un nombre entier (chiffres uniquement). Sinon : erreur sous le champ, et null.
// Les limites (2 à 4094, 1 à 64…) sont vérifiées par cisco.js.
function lireEntier(champ, exemple, champsEnErreur) {
  const texte = champ.value.trim();
  if (/^\d+$/.test(texte)) return Number(texte);
  afficherErreur(champ, texte === '' ? 'Ce champ est obligatoire.' : `Nombre entier attendu (ex. ${exemple}).`);
  champsEnErreur.push(champ);
  return null;
}

// Retrouve le champ de la page qui correspond à erreur.champ (ex. « vlans.1.ports »).
// lignesCochees : les lignes envoyées à cisco.js, dans l'ordre (« vlans.1 » = la 2e ligne cochée).
function trouverChamp(chemin, lignesCochees) {
  if (Object.hasOwn(champsReglages, chemin)) return champsReglages[chemin];
  const [debut, numero, propriete] = chemin.split('.');
  if (debut !== 'vlans') return null;
  // « vlans » seul (aucun VLAN, trop de VLAN) : la première ligne cochée.
  const ligne = lignesCochees[Number(numero)] ?? lignesCochees[0];
  if (!ligne) return null;
  const SELECTEURS = { id: '.js-vlan-id', nom: '.js-vlan-nom', ports: '.js-vlan-ports' };
  // Sous-réseau ou passerelle (repris du plan, pas modifiables ici) : sous la case de la ligne.
  return ligne.querySelector(SELECTEURS[propriete] ?? '.js-creer');
}

/* ----- Génération ----- */

formCisco.addEventListener('submit', (event) => {
  event.preventDefault();

  // On repart de zéro : plus aucune erreur affichée.
  for (const champ of formCisco.querySelectorAll('.input, .case')) effacerErreur(champ);
  erreurCisco.textContent = '';
  const champsEnErreur = [];

  // 1. Les lignes de VLAN : un choix par sous-réseau, null si la case est décochée (dans l'ordre de la page).
  const lignes = [...listeVlans.children];
  const lignesCochees = lignes.filter((ligne) => ligne.querySelector('.js-creer').checked);
  const premiereCase = lignes[0].querySelector('.js-creer');
  if (lignesCochees.length === 0) {
    afficherErreur(premiereCase, 'Coche au moins un sous-réseau pour créer un VLAN.');
    champsEnErreur.push(premiereCase);
  } else if (lignesCochees.length > VLANS_MAX) {
    afficherErreur(
      premiereCase,
      `${VLANS_MAX} VLAN au maximum : chacun a besoin d'un port access et le trunk en prend un. ` +
        `Décoche ${lignesCochees.length - VLANS_MAX} sous-réseau(x).`,
    );
    champsEnErreur.push(premiereCase);
  }
  const choix = [];
  const noms = [];
  for (const ligne of lignes) {
    if (!ligne.querySelector('.js-creer').checked) {
      choix.push(null);
      continue;
    }
    const id = lireEntier(ligne.querySelector('.js-vlan-id'), '10', champsEnErreur);
    noms.push(lireTexte(ligne.querySelector('.js-vlan-nom'), champsEnErreur));
    choix.push({ id, ports: lireTexte(ligne.querySelector('.js-vlan-ports'), champsEnErreur) });
  }

  // 2. Les réglages, lus dans l'ordre de la page (le focus ira sur la première erreur).
  const c = champsReglages;
  const hostnameSwitch = lireTexte(c['switch.hostname'], champsEnErreur);
  const hostnameRouteur = lireTexte(c['routeur.hostname'], champsEnErreur);
  const trunk = lireTexte(c['switch.trunk'], champsEnErreur);
  const domaine = lireTexte(c.domaine, champsEnErreur);
  const vlanNatif = { id: lireEntier(c['vlanNatif.id'], '99', champsEnErreur), nom: lireTexte(c['vlanNatif.nom'], champsEnErreur) };
  const management = {
    id: lireEntier(c['management.id'], '50', champsEnErreur),
    nom: lireTexte(c['management.nom'], champsEnErreur),
    reseau: lireTexte(c['management.reseau'], champsEnErreur),
  };
  const portSecurity = {
    maximum: lireEntier(c['portSecurity.maximum'], '2', champsEnErreur),
    violation: c['portSecurity.violation'].value,
    sticky: c['portSecurity.sticky'].checked,
  };
  const dns = lireTexte(c.dns, champsEnErreur);
  const banniere = lireTexte(c.banniere, champsEnErreur);

  if (champsEnErreur.length > 0) {
    resultatCisco.hidden = true;
    // Le focus va sur le premier champ en erreur : le lecteur d'écran lit le champ et son erreur.
    champsEnErreur[0].focus();
    return;
  }

  // 3. Du plan aux VLAN, puis génération. cisco.js revérifie TOUT (listes blanches, doublons, ports…).
  let configs;
  try {
    // depuisPlanVlsm() reprend le sous-réseau et la passerelle du plan ; le nom vient du champ, modifiable.
    const vlans = depuisPlanVlsm(planCisco, choix).map((vlan, i) => ({ ...vlan, nom: noms[i] }));
    configs = genererConfigurations({
      switch: { hostname: hostnameSwitch, trunk },
      routeur: { hostname: hostnameRouteur },
      domaine,
      vlans,
      vlanNatif,
      management,
      portSecurity,
      dns,
      banniere,
    });
  } catch (erreur) {
    resultatCisco.hidden = true;
    // erreur.champ (ex. « vlans.1.ports ») désigne la donnée refusée : on place le message sous son champ.
    const champ = erreur instanceof ErreurSaisie ? trouverChamp(erreur.champ, lignesCochees) : null;
    if (champ) {
      // detail : le message sans son sujet, que l'étiquette du champ donne déjà.
      afficherErreur(champ, majuscule(erreur.detail));
      champ.focus();
    } else {
      // Erreur qui ne correspond à aucun champ affiché : message complet sous le bouton.
      erreurCisco.textContent = erreur.message;
      erreurCisco.focus();
    }
    return;
  }

  // 4. Affichage. Les hostnames ont passé la liste blanche (lettres, chiffres, tirets) : noms de fichiers sûrs.
  configsCisco = {
    switch: { texte: configs.switch, fichier: `config-${hostnameSwitch}.txt` },
    routeur: { texte: configs.routeur, fichier: `config-${hostnameRouteur}.txt` },
  };
  document.getElementById('cisco-switch').textContent = configs.switch;
  document.getElementById('cisco-routeur').textContent = configs.routeur;
  document.getElementById('cisco-switch-titre').textContent = `Switch ${hostnameSwitch}`;
  document.getElementById('cisco-routeur-titre').textContent = `Routeur ${hostnameRouteur}`;
  document.getElementById('cisco-resume').textContent =
    `${lignesCochees.length} VLAN · management ${management.reseau} · plan ${planCisco.network}`;
  resultatCisco.hidden = false;
  annoncer(`Configurations générées pour ${hostnameSwitch} et ${hostnameRouteur}. À relire et à tester avant tout usage réel.`);
});

// Copier : le texte exact de la configuration, tel qu'il est affiché.
for (const bouton of document.querySelectorAll('.btn-copy[data-config]')) {
  bouton.addEventListener('click', () => {
    const config = configsCisco?.[bouton.dataset.config];
    if (config) copier(bouton, config.texte);
  });
}

// Télécharger en .txt : fichier texte brut, fabriqué dans le navigateur.
for (const bouton of document.querySelectorAll('.btn-txt')) {
  bouton.addEventListener('click', () => {
    const config = configsCisco?.[bouton.dataset.config];
    if (!config) return;
    telecharger(config.fichier, new Blob([config.texte], { type: 'text/plain;charset=utf-8' }));
    annoncer(`Téléchargement de ${config.fichier}`);
  });
}
