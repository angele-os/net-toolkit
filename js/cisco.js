// Générateur de configurations Cisco : fonctions pures (aucun accès à la page), testées dans tests/cisco.test.js.
// Matériel visé : un switch Catalyst 2960-24TT (Fa0/1 à Fa0/24, Gi0/1, Gi0/2) relié par un trunk à un
// routeur ISR 4321 (interface G0/0/0) qui route les VLAN grâce à des sous-interfaces (« router-on-a-stick »).
//
// SÉCURITÉ : le risque principal est l'INJECTION DE COMMANDES. Une configuration IOS se lit ligne par
// ligne : si un nom de VLAN valait « Bureau\nusername pirate secret 123 », le retour à la ligne (\n)
// ferait de la suite une vraie commande, qui créerait un compte. D'où trois règles :
//   1. les textes saisis (hostname, noms, domaine, bannière) sont vérifiés par LISTE BLANCHE : on liste
//      les caractères permis et on refuse tout le reste (plus sûr que de chercher les caractères dangereux) ;
//   2. les adresses IP et les ports sont relus en nombres, puis c'est le programme qui les réécrit ;
//   3. aucun mot de passe n'est demandé : chaque secret est un marqueur <A_REMPLACER> à remplir à la main.
//
// Packet Tracer : les commandes générées sont choisies pour y être acceptées. Celles qu'il ne connaît pas
// sont seulement citées dans les commentaires « ! » de la configuration produite.
// Ces commentaires sont écrits sans accents : une console série affiche mal les caractères non ASCII.
import { parseCidr, parseIp, ipToString, prefixToMask, addressType } from './ip.js';

/* ---------- Matériel ---------- */

// Ports du Catalyst 2960-24TT, par type : abréviation saisie, nom complet IOS, nombre de ports.
const TYPES_PORTS = [
  { court: 'Fa', long: 'FastEthernet', nombre: 24 },
  { court: 'Gi', long: 'GigabitEthernet', nombre: 2 },
];

// Tous les ports dans l'ordre : Fa0/1 … Fa0/24, Gi0/1, Gi0/2 (26 ports).
export const PORTS_SWITCH = TYPES_PORTS.flatMap((type) =>
  // Array.from({ length: n }, …) fabrique n éléments : i va de 0 à n − 1, le port porte donc le numéro i + 1.
  Array.from({ length: type.nombre }, (_, i) => `${type.court}0/${i + 1}`),
);

// Interface du routeur ISR 4321 reliée au trunk du switch.
export const INTERFACE_ROUTEUR = 'GigabitEthernet0/0/0';

/* ---------- Limites et valeurs par défaut (exportées : l'interface et les tests utilisent les mêmes) ---------- */

// Marqueur à remplacer à la main par un vrai secret, AVANT de coller la configuration.
export const MARQUEUR = '<A_REMPLACER>';
export const HOSTNAME_LONGUEUR_MAX = 63;
export const NOM_VLAN_LONGUEUR_MAX = 32;
export const DOMAINE_LONGUEUR_MAX = 64;
export const BANNIERE_LONGUEUR_MAX = 200;
// Caractère qui ouvre et ferme la bannière : « banner motd #texte# ».
export const DELIMITEUR_BANNIERE = '#';
// Adresses MAC par port pour Port Security : limite prudente, acceptée par tous les 2960.
export const MAC_PAR_PORT_MAX = 64;
// Réactions possibles de Port Security quand un appareil de trop se branche.
export const VIOLATIONS = ['protect', 'restrict', 'shutdown'];
// Chaque VLAN a au moins un port access et le trunk occupe un port : 26 − 1 = 25 VLAN au plus.
export const VLANS_MAX = PORTS_SWITCH.length - 1;

// Préfixe le plus large accepté : /8, la taille du plus grand bloc privé (10.0.0.0/8).
const PREFIXE_MIN = 8;
// Préfixe le plus étroit : /30, soit 2 adresses utilisables (la passerelle et un appareil).
const PREFIXE_MAX = 30;
// Déconnexion automatique d'une session inactive (console ou SSH), en minutes.
const DELAI_INACTIVITE = 5;

export const DEFAUTS = Object.freeze({
  trunk: 'Gi0/1',
  vlanNatif: Object.freeze({ id: 99, nom: 'NATIVE' }),
  vlanParking: Object.freeze({ id: 999, nom: 'PARKING' }),
  nomManagement: 'MANAGEMENT',
  domaine: 'entreprise.lan',
  portSecurity: Object.freeze({ maximum: 2, violation: 'shutdown', sticky: true }),
  banniere: 'Acces reserve au personnel autorise.',
});

/* ---------- Listes blanches : chaque expression teste UN caractère ---------- */

const LETTRE = /^[A-Za-z]$/;
const CAR_HOSTNAME = /^[A-Za-z0-9-]$/;
const CAR_NOM_VLAN = /^[A-Za-z0-9_-]$/;
const CAR_DOMAINE = /^[A-Za-z0-9.-]$/;
// Bannière : lettres sans accent, chiffres, espace et ponctuation courante. Sont exclus « # » (le délimiteur)
// et « ? » (en le tapant, la console IOS affiche l'aide au lieu de l'écrire).
const CAR_BANNIERE = /^[A-Za-z0-9 .,;:!'()/@+=*_-]$/;

const REGLE_HOSTNAME = `une lettre, puis des lettres sans accent, des chiffres ou des tirets (${HOSTNAME_LONGUEUR_MAX} caractères au maximum)`;
const REGLE_NOM_VLAN = `lettres sans accent, chiffres, « _ » et « - » (${NOM_VLAN_LONGUEUR_MAX} caractères au maximum)`;
const REGLE_DOMAINE = 'des mots de lettres sans accent, chiffres ou tirets, séparés par des points (ex. « entreprise.lan »)';
const REGLE_BANNIERE = `une seule ligne de lettres sans accent, chiffres, espaces et ponctuation . , ; : ! ' ( ) / @ + = * _ - (${BANNIERE_LONGUEUR_MAX} caractères au maximum)`;

/* ---------- Outils pour les messages d'erreur ---------- */

// Caractères invisibles qu'on sait nommer.
const CARACTERES_NOMMES = {
  '\n': 'le retour à la ligne (U+000A)',
  '\r': 'le retour chariot (U+000D)',
  '\t': 'la tabulation (U+0009)',
  ' ': 'l’espace',
};

/**
 * Décrit un caractère refusé SANS l'afficher s'il est invisible : un retour à la ligne ou U+202E
 * (qui inverse le sens du texte) abîmeraient le message lui-même.
 */
function decrireCaractere(c) {
  if (CARACTERES_NOMMES[c]) return CARACTERES_NOMMES[c];
  // Lettre, chiffre, ponctuation ou symbole visible : on peut l'afficher entre guillemets.
  if (/^[\p{L}\p{N}\p{P}\p{S}]$/u.test(c)) return `le caractère « ${c} »`;
  // Sinon on donne son code hexadécimal sur 4 chiffres : U+0000, U+202E…
  return `le caractère invisible U+${c.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')}`;
}

// Recopie une saisie dans un message seulement si elle est courte et faite de caractères ASCII visibles.
function citer(valeur) {
  return typeof valeur === 'string' && /^[\x20-\x7E]{1,40}$/.test(valeur) ? ` « ${valeur} »` : '';
}

/* ---------- Vérification des textes ---------- */

/**
 * Vérifie un texte par liste blanche et le renvoie tel quel s'il est valide.
 * quoi : ce qui est vérifié, en tête du message (ex. « Hostname du switch ») ;
 * caractere : expression qui teste UN caractère autorisé ; regle : la règle expliquée en clair.
 */
function verifierTexte(valeur, quoi, max, caractere, regle) {
  if (typeof valeur !== 'string') throw new Error(`${quoi} : un texte est attendu.`);
  if (valeur === '') throw new Error(`${quoi} : le texte est vide.`);
  // La longueur est vérifiée AVANT le reste : un texte énorme est refusé sans être parcouru.
  if (valeur.length > max) throw new Error(`${quoi} : ${max} caractères au maximum (${valeur.length} saisis).`);
  // « for…of » parcourt le texte caractère par caractère (un emoji compte pour un seul caractère).
  for (const c of valeur) {
    if (!caractere.test(c)) throw new Error(`${quoi} : ${decrireCaractere(c)} n’est pas autorisé. Règle : ${regle}.`);
  }
  return valeur;
}

function verifierHostname(valeur, quoi) {
  verifierTexte(valeur, quoi, HOSTNAME_LONGUEUR_MAX, CAR_HOSTNAME, REGLE_HOSTNAME);
  if (!LETTRE.test(valeur[0])) {
    throw new Error(`${quoi} : le premier caractère doit être une lettre. Règle : ${REGLE_HOSTNAME}.`);
  }
  return valeur;
}

function verifierNomVlan(valeur, ref) {
  return verifierTexte(valeur, `Nom du ${ref}`, NOM_VLAN_LONGUEUR_MAX, CAR_NOM_VLAN, REGLE_NOM_VLAN);
}

function lireDomaine(valeur) {
  if (valeur === undefined) return DEFAUTS.domaine;
  verifierTexte(valeur, 'Domaine', DOMAINE_LONGUEUR_MAX, CAR_DOMAINE, REGLE_DOMAINE);
  // Chaque partie entre deux points : lettre ou chiffre aux deux bouts, tirets permis au milieu.
  for (const partie of valeur.split('.')) {
    if (!/^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$/.test(partie)) {
      // Recopier « valeur » est sans risque : la liste blanche ci-dessus vient de la vérifier.
      throw new Error(`Domaine : « ${valeur} » est mal formé. Règle : ${REGLE_DOMAINE}.`);
    }
  }
  return valeur;
}

function lireBanniere(valeur) {
  if (valeur === undefined) return DEFAUTS.banniere;
  // Le délimiteur est testé à part, pour un message plus parlant que la règle générale.
  if (typeof valeur === 'string' && valeur.includes(DELIMITEUR_BANNIERE)) {
    throw new Error(
      `Bannière : le caractère « ${DELIMITEUR_BANNIERE} » est interdit, il marque le début et la fin de la bannière ` +
        `(banner motd ${DELIMITEUR_BANNIERE}texte${DELIMITEUR_BANNIERE}) : la suite deviendrait des commandes.`,
    );
  }
  return verifierTexte(valeur, 'Bannière', BANNIERE_LONGUEUR_MAX, CAR_BANNIERE, REGLE_BANNIERE);
}

/* ---------- Vérification des nombres et des adresses ---------- */

function verifierIdVlan(id, ref) {
  const quoi = `Identifiant du ${ref}`;
  if (!Number.isInteger(id)) throw new Error(`${quoi} : un nombre entier de 2 à 4094 est attendu.`);
  if (id < 2 || id > 4094) {
    throw new Error(`${quoi} : ${id} est hors limites, de 2 à 4094 (le VLAN 1, VLAN par défaut, est à laisser de côté).`);
  }
  if (id >= 1002 && id <= 1005) {
    throw new Error(`${quoi} : les VLAN 1002 à 1005 sont réservés par Cisco (anciennes technologies FDDI et Token Ring).`);
  }
  return id;
}

/**
 * Lit un sous-réseau « 192.168.10.0/25 » et sa passerelle (facultative : 1re adresse utilisable par défaut).
 * Renvoie des nombres : le texte saisi ne sera jamais recopié dans la configuration.
 */
function lireSousReseau(texte, passerelleTexte, ref) {
  const quoi = `Sous-réseau du ${ref}`;
  if (typeof texte !== 'string') throw new Error(`${quoi} : un texte comme « 192.168.10.0/25 » est attendu.`);
  let lu;
  try {
    lu = parseCidr(texte);
  } catch (erreur) {
    throw new Error(`${quoi} : ${erreur.message}`);
  }
  const { ip, prefix } = lu;
  if (prefix < PREFIXE_MIN || prefix > PREFIXE_MAX) {
    throw new Error(
      `${quoi} : préfixe /${prefix} refusé, il faut entre /${PREFIXE_MIN} et /${PREFIXE_MAX} ` +
        '(au moins 2 adresses utilisables : la passerelle et un appareil).',
    );
  }
  // Masque du sous-réseau : ex. /25 → 255.255.255.128.
  const masque = prefixToMask(prefix);
  // Adresse réseau : IP ET masque (on efface la partie hôte), « >>> 0 » la garde en non signé.
  const reseau = (ip & masque) >>> 0;
  if (reseau !== ip) {
    throw new Error(
      `${quoi} : ${ipToString(ip)}/${prefix} n'est pas une adresse de réseau. Voulais-tu dire ${ipToString(reseau)}/${prefix} ?`,
    );
  }
  // Broadcast : réseau OU l'inverse du masque (toute la partie hôte à 1), en non signé.
  const broadcast = (reseau | ~masque) >>> 0;
  // Première adresse utilisable : juste après l'adresse réseau.
  const premiere = reseau + 1;
  // Dernière adresse utilisable : juste avant le broadcast.
  const derniere = broadcast - 1;

  // Sans passerelle indiquée, on prend la convention courante : la première adresse utilisable.
  let passerelle = premiere;
  if (passerelleTexte !== undefined) {
    if (typeof passerelleTexte !== 'string') throw new Error(`Passerelle du ${ref} : une adresse IP est attendue.`);
    try {
      passerelle = parseIp(passerelleTexte);
    } catch (erreur) {
      throw new Error(`Passerelle du ${ref} : ${erreur.message}`);
    }
    // Elle doit être une adresse utilisable de CE sous-réseau (ni le réseau, ni le broadcast, ni ailleurs).
    if (passerelle < premiere || passerelle > derniere) {
      throw new Error(
        `Passerelle du ${ref} : ${ipToString(passerelle)} n'est pas une adresse utilisable de ` +
          `${ipToString(reseau)}/${prefix} (de ${ipToString(premiere)} à ${ipToString(derniere)}).`,
      );
    }
  }
  return { reseau, prefixe: prefix, masque, broadcast, derniere, passerelle };
}

// Adresses impossibles pour un serveur DNS, avec leur description en français.
const TYPES_DNS_REFUSES = {
  loopback: 'de bouclage (la machine elle-même)',
  multicast: 'multicast (destinée à un groupe)',
  reserved: 'réservée',
  'link-local': 'locale au lien (attribuée faute de DHCP)',
};

function lireDns(valeur) {
  if (typeof valeur !== 'string') throw new Error('Serveur DNS : une adresse IP est attendue (ex. « 1.1.1.1 »).');
  let ip;
  try {
    ip = parseIp(valeur);
  } catch (erreur) {
    throw new Error(`Serveur DNS : ${erreur.message}`);
  }
  const type = addressType(ip);
  if (TYPES_DNS_REFUSES[type]) {
    throw new Error(`Serveur DNS : ${ipToString(ip)} est une adresse ${TYPES_DNS_REFUSES[type]}, pas celle d'un serveur.`);
  }
  return ip;
}

function lirePortSecurity(options) {
  if (options === undefined) return { ...DEFAUTS.portSecurity };
  if (options === null || typeof options !== 'object') throw new Error('Port Security : un objet d’options est attendu.');
  // Chaque option absente prend sa valeur par défaut (« ?? » : seulement si elle vaut undefined ou null).
  const maximum = options.maximum ?? DEFAUTS.portSecurity.maximum;
  const violation = options.violation ?? DEFAUTS.portSecurity.violation;
  const sticky = options.sticky ?? DEFAUTS.portSecurity.sticky;
  if (!Number.isInteger(maximum) || maximum < 1 || maximum > MAC_PAR_PORT_MAX) {
    throw new Error(`Port Security : le maximum doit être un nombre entier de 1 à ${MAC_PAR_PORT_MAX} adresses MAC par port.`);
  }
  if (!VIOLATIONS.includes(violation)) {
    throw new Error(`Port Security : mode de violation${citer(violation)} inconnu, choisis protect, restrict ou shutdown.`);
  }
  if (typeof sticky !== 'boolean') throw new Error('Port Security : sticky doit valoir true (oui) ou false (non).');
  return { maximum, violation, sticky };
}

/* ---------- Ports du switch ---------- */

// Une plage « Fa0/1-12 » (espaces permis autour du tiret) ou un port seul « Gi0/2 », majuscules indifférentes.
// [1-9]\d? : un numéro de 1 à 99 sans zéro en tête ; on vérifie ensuite qu'il existe sur le modèle.
const PLAGE = /^(fa|gi)0\/([1-9]\d?)(?: ?- ?([1-9]\d?))?$/i;

/**
 * Lit une plage de ports. Renvoie { type, debut, fin } : un seul type de port, numéros croissants.
 */
function lirePlage(texte, quoi) {
  const exemple = 'écris par exemple « Fa0/1-12 » ou « Gi0/2 »';
  // 20 caractères suffisent largement (« Fa0/10 - 24 » en fait 11) : au-delà, on refuse sans analyser.
  const morceaux = typeof texte === 'string' && texte.length <= 20 ? texte.match(PLAGE) : null;
  if (!morceaux) throw new Error(`${quoi} :${citer(texte)} n'est pas une plage valide, ${exemple}.`);
  // Le type d'après l'abréviation : Fa ou Gi, quelle que soit la casse.
  const type = TYPES_PORTS.find((t) => t.court.toLowerCase() === morceaux[1].toLowerCase());
  const debut = Number(morceaux[2]);
  // Sans « -fin », la plage ne contient qu'un port.
  const fin = morceaux[3] === undefined ? debut : Number(morceaux[3]);
  // Le plus grand des deux numéros doit exister sur le 2960-24TT.
  const plusGrand = Math.max(debut, fin);
  if (plusGrand > type.nombre) {
    throw new Error(
      `${quoi} : le port ${type.court}0/${plusGrand} n'existe pas sur un 2960-24TT ` +
        `(${type.court}0/1 à ${type.court}0/${type.nombre}).`,
    );
  }
  if (debut > fin) {
    throw new Error(`${quoi} : la plage ${type.court}0/${debut}-${fin} est à l'envers, écris ${type.court}0/${fin}-${debut}.`);
  }
  return { type, debut, fin };
}

// Nom court d'un port, utilisé comme clé : « Fa0/5 ».
const nomPort = (type, numero) => `${type.court}0/${numero}`;

/**
 * Réserve les ports du trunk puis de chaque VLAN ; refuse un port pris deux fois.
 * Renvoie la table « port → occupant ».
 */
function attribuerPorts(vlans, trunk) {
  const occupants = new Map([[nomPort(trunk.type, trunk.debut), 'le port trunk']]);
  for (const vlan of vlans) {
    for (let n = vlan.plage.debut; n <= vlan.plage.fin; n++) {
      const port = nomPort(vlan.plage.type, n);
      if (occupants.has(port)) throw new Error(`Ports du ${vlan.ref} : ${port} est déjà pris par ${occupants.get(port)}.`);
      occupants.set(port, `le ${vlan.ref}`);
    }
  }
  return occupants;
}

/**
 * Regroupe les ports libres en plages continues. Ex. Fa0/23, Fa0/24 et Gi0/2 → Fa0/23-24 et Gi0/2.
 */
function plagesLibres(occupants) {
  const plages = [];
  for (const type of TYPES_PORTS) {
    // Début de la plage libre en cours, ou null si on n'est pas dans une plage libre.
    let debut = null;
    // On va jusqu'à nombre + 1 : ce port fictif, jamais libre, ferme la dernière plage.
    for (let n = 1; n <= type.nombre + 1; n++) {
      const libre = n <= type.nombre && !occupants.has(nomPort(type, n));
      if (libre && debut === null) debut = n;
      if (!libre && debut !== null) {
        plages.push({ type, debut, fin: n - 1 });
        debut = null;
      }
    }
  }
  return plages;
}

/* ---------- Lecture complète de l'entrée ---------- */

function lireVlanSimple(valeur, defaut, ref) {
  // VLAN absent : valeurs par défaut. Nom absent : nom par défaut.
  const source = valeur ?? defaut;
  return { ref, id: verifierIdVlan(source?.id, ref), nom: verifierNomVlan(source?.nom ?? defaut.nom, ref) };
}

function lireManagement(valeur) {
  const ref = 'VLAN de management';
  if (valeur === null || typeof valeur !== 'object') {
    throw new Error(`${ref} manquant : indique son identifiant et son sous-réseau (ex. « 192.168.10.224/28 »).`);
  }
  const id = verifierIdVlan(valeur.id, ref);
  const nom = verifierNomVlan(valeur.nom ?? DEFAUTS.nomManagement, ref);
  const sousReseau = lireSousReseau(valeur.reseau, valeur.passerelle, ref);
  // Le switch prend la dernière adresse utilisable : la passerelle (le routeur) doit en avoir une autre.
  if (sousReseau.passerelle === sousReseau.derniere) {
    throw new Error(
      `Passerelle du ${ref} : ${ipToString(sousReseau.passerelle)} est l'adresse du switch ` +
        '(dernière adresse utilisable), choisis-en une autre.',
    );
  }
  return { ref, id, nom, sousReseau };
}

function lireVlans(liste) {
  if (!Array.isArray(liste) || liste.length === 0) throw new Error('Aucun VLAN : ajoute au moins un VLAN avec ses ports.');
  if (liste.length > VLANS_MAX) {
    throw new Error(`Trop de VLAN : ${VLANS_MAX} au maximum (un port chacun, plus le trunk), ${liste.length} reçus.`);
  }
  return liste.map((vlan, i) => {
    // Numéro « humain » (à partir de 1), pour retrouver la ligne en cause.
    const ref = `VLAN n°${i + 1}`;
    return {
      ref,
      id: verifierIdVlan(vlan?.id, ref),
      nom: verifierNomVlan(vlan?.nom, ref),
      sousReseau: lireSousReseau(vlan?.reseau, vlan?.passerelle, ref),
      plage: lirePlage(vlan?.ports, `Ports du ${ref}`),
    };
  });
}

// Aucun identifiant ni nom deux fois. Le message cite le VLAN qui l'avait en premier.
function verifierDoublons(vlans) {
  const ids = new Map();
  const noms = new Map();
  for (const vlan of vlans) {
    if (ids.has(vlan.id)) throw new Error(`Identifiant du ${vlan.ref} : ${vlan.id} est déjà pris par le ${ids.get(vlan.id)}.`);
    ids.set(vlan.id, vlan.ref);
    // « Bureau » et « BUREAU » sont considérés comme le même nom.
    const cle = vlan.nom.toLowerCase();
    if (noms.has(cle)) throw new Error(`Nom du ${vlan.ref} : « ${vlan.nom} » est déjà pris par le ${noms.get(cle)}.`);
    noms.set(cle, vlan.ref);
  }
}

// Deux sous-interfaces du routeur ne peuvent pas avoir des sous-réseaux qui se recouvrent.
function verifierChevauchements(vlans) {
  for (let i = 0; i < vlans.length; i++) {
    for (let j = 0; j < i; j++) {
      const a = vlans[i].sousReseau;
      const b = vlans[j].sousReseau;
      // Deux plages [début, fin] se recouvrent si chacune commence avant que l'autre ne finisse.
      if (a.reseau <= b.broadcast && b.reseau <= a.broadcast) {
        throw new Error(
          `Sous-réseau du ${vlans[i].ref} : ${ipToString(a.reseau)}/${a.prefixe} chevauche celui du ` +
            `${vlans[j].ref} (${ipToString(b.reseau)}/${b.prefixe}).`,
        );
      }
    }
  }
}

/**
 * Vérifie toute l'entrée et la convertit en valeurs sûres. Lève une erreur claire au premier problème.
 */
function lireEntree(entree) {
  if (entree === null || typeof entree !== 'object') {
    throw new Error('Entrée invalide : un objet décrivant le switch et le routeur est attendu.');
  }
  // « ?. » : si entree.switch est absent, on lit undefined au lieu de planter.
  const hostnameSwitch = verifierHostname(entree.switch?.hostname, 'Hostname du switch');
  const hostnameRouteur = verifierHostname(entree.routeur?.hostname, 'Hostname du routeur');
  if (hostnameSwitch.toLowerCase() === hostnameRouteur.toLowerCase()) {
    throw new Error('Hostname du routeur : il doit être différent de celui du switch.');
  }
  const natif = lireVlanSimple(entree.vlanNatif, DEFAUTS.vlanNatif, 'VLAN natif');
  const parking = lireVlanSimple(entree.vlanParking, DEFAUTS.vlanParking, 'VLAN parking');
  const management = lireManagement(entree.management);
  const vlans = lireVlans(entree.vlans);
  // Ordre d'enregistrement : natif, parking, management, puis les VLAN saisis.
  verifierDoublons([natif, parking, management, ...vlans]);
  verifierChevauchements([...vlans, management]);

  const trunk = lirePlage(entree.switch?.trunk ?? DEFAUTS.trunk, 'Port trunk');
  if (trunk.debut !== trunk.fin) throw new Error('Port trunk : un seul port est attendu (ex. « Gi0/1 »).');
  const occupants = attribuerPorts(vlans, trunk);

  return {
    hostnameSwitch,
    hostnameRouteur,
    domaine: lireDomaine(entree.domaine),
    banniere: lireBanniere(entree.banniere),
    dns: lireDns(entree.dns),
    portSecurity: lirePortSecurity(entree.portSecurity),
    natif,
    parking,
    management,
    vlans,
    trunk,
    libres: plagesLibres(occupants),
  };
}

/* ---------- Écriture des configurations ---------- */

// « interface FastEthernet0/5 » pour un port seul, « interface range FastEthernet0/1 - 12 » pour une plage.
function ligneInterface({ type, debut, fin }) {
  return debut === fin ? `interface ${type.long}0/${debut}` : `interface range ${type.long}0/${debut} - ${fin}`;
}

const EXPLICATION_VIOLATION = {
  protect: `trames de l'intrus ignorees, sans alerte`,
  restrict: `trames de l'intrus ignorees, avec alerte dans les journaux`,
  shutdown: `port coupe (err-disabled) jusqu'a intervention`,
};

function entete(appareil, modele) {
  return [
    '!==================================================================',
    `! net-toolkit : configuration du ${appareil}`,
    `! Modele : ${modele}`,
    `! 1. Remplace chaque ${MARQUEUR} (voir les commentaires SECRET).`,
    '! 2. Colle le tout en mode configuration globale (enable, puis configure terminal).',
    '!==================================================================',
  ];
}

// Bloc commun au switch et au routeur. derniereVty : numéro de la dernière ligne d'accès à distance.
function lignesBase(hostname, c, derniereVty) {
  return [
    '!',
    '! ---------- 1. Base et durcissement ----------',
    `hostname ${hostname}`,
    '! Pas de recherche DNS sur une commande mal tapee (evite une attente inutile).',
    'no ip domain-lookup',
    '! Masque les mots de passe de type "password" dans la configuration (chiffrement faible, type 7).',
    'service password-encryption',
    '! SECRET : mot de passe du mode privilegie, stocke sous forme de hachage.',
    '! Sur un IOS recent, prefere "enable algorithm-type scrypt secret" (non pris en charge par Packet Tracer).',
    `enable secret ${MARQUEUR}`,
    `! SECRET : compte local pour la console et SSH (1er marqueur = nom d'utilisateur, 2e = mot de passe).`,
    `username ${MARQUEUR} secret ${MARQUEUR}`,
    '! Le domaine et le hostname servent a nommer la cle RSA de SSH.',
    `ip domain-name ${c.domaine}`,
    '! Cle RSA de 2048 bits, indispensable a SSH. Si une cle existe deja, IOS demande confirmation.',
    'crypto key generate rsa general-keys modulus 2048',
    '! SSH version 2 uniquement : la version 1 a des failles connues.',
    'ip ssh version 2',
    '! Avertissement affiche avant toute connexion.',
    `banner motd ${DELIMITEUR_BANNIERE}${c.banniere}${DELIMITEUR_BANNIERE}`,
    '!',
    `! Console : compte local, deconnexion apres ${DELAI_INACTIVITE} min d'inactivite,`,
    '! messages systeme qui ne coupent pas la saisie (logging synchronous).',
    'line console 0',
    ' login local',
    ` exec-timeout ${DELAI_INACTIVITE} 0`,
    ' logging synchronous',
    '!',
    '! Acces a distance (VTY) : SSH uniquement, Telnet refuse car il circule en clair.',
    `line vty 0 ${derniereVty}`,
    ' login local',
    ' transport input ssh',
    ` exec-timeout ${DELAI_INACTIVITE} 0`,
    ' logging synchronous',
    '!',
  ];
}

const lignesFin = () => [
  'end',
  '! Pour garder la configuration apres un redemarrage : copy running-config startup-config',
];

function configSwitch(c) {
  const { natif, parking, management: m, portSecurity: ps } = c;
  const trunk = `${c.trunk.type.long}0/${c.trunk.debut}`;
  // VLAN autorisés sur le trunk : ceux des postes, le management et le natif, triés par numéro.
  const autorises = [...c.vlans.map((v) => v.id), m.id, natif.id].sort((a, b) => a - b);

  const lignes = [
    ...entete(`switch ${c.hostnameSwitch}`, 'Cisco Catalyst 2960-24TT (Fa0/1-24, Gi0/1-2), syntaxe IOS 15'),
    ...lignesBase(c.hostnameSwitch, c, 15),

    '! ---------- 2. VLAN ----------',
    '! VTP transparent : le switch ignore les annonces VTP (un autre switch ne peut pas effacer ses VLAN)',
    '! et accepte les VLAN etendus (1006 a 4094).',
    'vtp mode transparent',
    ...c.vlans.flatMap((v) => [`vlan ${v.id}`, ` name ${v.nom}`]),
    `! VLAN de management : adresse d'administration du switch.`,
    `vlan ${m.id}`,
    ` name ${m.nom}`,
    '! VLAN natif du trunk : trames non etiquetees, aucun appareil dedans.',
    `vlan ${natif.id}`,
    ` name ${natif.nom}`,
    `! VLAN parking : accueille les ports inutilises, il n'est route nulle part.`,
    `vlan ${parking.id}`,
    ` name ${parking.nom}`,
    '!',

    '! ---------- 3. Ports access (postes de travail) ----------',
    `! Port Security : ${ps.maximum} adresse(s) MAC au maximum par port ; en cas d'intrus, ${ps.violation} :`,
    `! ${EXPLICATION_VIOLATION[ps.violation]}.`,
    ...(ps.sticky ? ['! Sticky : les adresses MAC apprises sont ecrites dans la configuration.'] : []),
    '! PortFast : le port transmet tout de suite (il relie un poste, pas un switch).',
    `! BPDU Guard : le port se coupe s'il recoit un BPDU, c'est-a-dire si on y branche un switch.`,
    ...c.vlans.flatMap((v) => [
      ligneInterface(v.plage),
      ` description VLAN ${v.id} ${v.nom}`,
      ' switchport mode access',
      ` switchport access vlan ${v.id}`,
      ' switchport port-security',
      ` switchport port-security maximum ${ps.maximum}`,
      ` switchport port-security violation ${ps.violation}`,
      ...(ps.sticky ? [' switchport port-security mac-address sticky'] : []),
      ' spanning-tree portfast',
      ' spanning-tree bpduguard enable',
      ' no shutdown',
      '!',
    ]),

    `! ---------- 4. Trunk vers le routeur ${c.hostnameRouteur} ----------`,
    `! Le 2960 ne connait que 802.1Q : "switchport trunk encapsulation dot1q" n'existe pas sur ce modele.`,
    '! nonegotiate : DTP desactive, le trunk est impose et jamais negocie.',
    `! Seuls les VLAN utiles passent : le VLAN parking ${parking.id} est exclu.`,
    `interface ${trunk}`,
    ` description Trunk vers ${c.hostnameRouteur} ${INTERFACE_ROUTEUR}`,
    ' switchport mode trunk',
    ' switchport nonegotiate',
    ` switchport trunk native vlan ${natif.id}`,
    ` switchport trunk allowed vlan ${autorises.join(',')}`,
    ' no shutdown',
    '!',

    '! ---------- 5. Ports inutilises ----------',
    `! Coupes et ranges dans le VLAN parking ${parking.id} : y brancher un cable ne donne acces a rien.`,
    ...(c.libres.length === 0 ? ['! Aucun port inutilise.', '!'] : []),
    ...c.libres.flatMap((plage) => [
      ligneInterface(plage),
      ' description Port inutilise',
      ' switchport mode access',
      ` switchport access vlan ${parking.id}`,
      ' shutdown',
      '!',
    ]),

    '! ---------- 6. Spanning Tree ----------',
    '! Rapid PVST+ : un arbre RSTP par VLAN, reconvergence en quelques secondes.',
    'spanning-tree mode rapid-pvst',
    '!',

    '! ---------- 7. Management ----------',
    `! Adresse d'administration du switch : derniere adresse utilisable du VLAN ${m.id}.`,
    `interface Vlan${m.id}`,
    ` description VLAN ${m.id} ${m.nom}`,
    ` ip address ${ipToString(m.sousReseau.derniere)} ${ipToString(m.sousReseau.masque)}`,
    ' no shutdown',
    '!',
    '! Passerelle pour joindre le switch depuis les autres VLAN (sous-interface du routeur).',
    `ip default-gateway ${ipToString(m.sousReseau.passerelle)}`,
    '!',
    ...lignesFin(),
  ];
  return lignes;
}

function configRouteur(c) {
  const { natif, management: m } = c;
  const trunk = `${c.trunk.type.long}0/${c.trunk.debut}`;
  const dns = ipToString(c.dns);

  return [
    ...entete(`routeur ${c.hostnameRouteur}`, `Cisco ISR 4321 (IOS XE, meme syntaxe qu'IOS 15)`),
    // ISR 4321 : 5 lignes d'accès à distance par défaut (vty 0 à 4).
    ...lignesBase(c.hostnameRouteur, c, 4),

    '! ---------- 2. Interface physique vers le switch ----------',
    `! Pas d'adresse ici : chaque VLAN a la sienne sur une sous-interface.`,
    `interface ${INTERFACE_ROUTEUR}`,
    ` description Trunk vers ${c.hostnameSwitch} ${trunk}`,
    ' no ip address',
    ' no shutdown',
    '!',

    '! ---------- 3. Sous-interfaces 802.1Q (une par VLAN) ----------',
    '! Chaque sous-interface lit les trames etiquetees de son VLAN ; son adresse est la passerelle du VLAN.',
    ...[...c.vlans, m].flatMap((v) => [
      `interface ${INTERFACE_ROUTEUR}.${v.id}`,
      ` description VLAN ${v.id} ${v.nom}`,
      ` encapsulation dot1Q ${v.id}`,
      ` ip address ${ipToString(v.sousReseau.passerelle)} ${ipToString(v.sousReseau.masque)}`,
      '!',
    ]),
    `! VLAN natif : meme numero que sur le switch, sans adresse IP (aucun trafic utile n'y circule).`,
    `interface ${INTERFACE_ROUTEUR}.${natif.id}`,
    ` description VLAN ${natif.id} ${natif.nom}`,
    ` encapsulation dot1Q ${natif.id} native`,
    '!',

    '! ---------- 4. DHCP ----------',
    `! Exclusions d'abord : la passerelle ne sera jamais distribuee a un poste.`,
    ...c.vlans.map((v) => `ip dhcp excluded-address ${ipToString(v.sousReseau.passerelle)}`),
    '!',
    `! Un pool par VLAN de postes. Pas de pool pour le management (VLAN ${m.id}) : adresses fixes.`,
    ...c.vlans.flatMap((v) => [
      `ip dhcp pool VLAN${v.id}_${v.nom}`,
      ` network ${ipToString(v.sousReseau.reseau)} ${ipToString(v.sousReseau.masque)}`,
      ` default-router ${ipToString(v.sousReseau.passerelle)}`,
      ` dns-server ${dns}`,
      '!',
    ]),
    ...lignesFin(),
  ];
}

/**
 * Dernier filet de sécurité (défense en profondeur) : la configuration est écrite entièrement en ASCII,
 * donc chaque ligne ne doit contenir que des caractères ASCII visibles ou des espaces (codes 0x20 à 0x7E).
 * Cela exclut tout retour à la ligne caché, caractère de contrôle ou séparateur Unicode (U+2028).
 * Si cela arrive malgré les listes blanches, c'est un bug : on préfère refuser que livrer.
 */
function assembler(lignes) {
  for (const ligne of lignes) {
    if (!/^[\x20-\x7E]*$/.test(ligne)) throw new Error('Erreur interne : caractère interdit dans la configuration générée.');
  }
  return `${lignes.join('\n')}\n`;
}

/**
 * Génère les deux configurations IOS. Lève une erreur claire (en français) si l'entrée est invalide.
 * @returns {{switch: string, routeur: string}}
 */
export function genererConfigurations(entree) {
  const c = lireEntree(entree);
  return { switch: assembler(configSwitch(c)), routeur: assembler(configRouteur(c)) };
}

/* ---------- Passerelle depuis le calcul VLSM ---------- */

// Ligatures que la décomposition des accents ne sépare pas.
const LIGATURES = { œ: 'oe', Œ: 'OE', æ: 'ae', Æ: 'AE', ß: 'ss' };

/**
 * Dérive un nom de VLAN d'un nom de sous-réseau : « Wi-Fi invités » → « Wi-Fi_invites ».
 * Accents retirés, espaces remplacés par « _ », autres caractères supprimés, 32 caractères au plus.
 */
export function nomVlanDepuis(nom) {
  if (typeof nom !== 'string') return '';
  return (
    nom
      // œ → oe, æ → ae, ß → ss.
      .replace(/[œŒæÆß]/g, (c) => LIGATURES[c])
      // NFD sépare chaque lettre accentuée en lettre + accent : « é » devient « e » suivi de « ´ ».
      .normalize('NFD')
      // \p{M} : les accents ainsi séparés, qu'on supprime.
      .replace(/\p{M}/gu, '')
      // Tout ce qui n'est ni lettre sans accent, ni chiffre, ni _ ou -, ni espace disparaît.
      .replace(/[^A-Za-z0-9_\-\s]/g, '')
      .trim()
      // Chaque suite d'espaces (ou de tabulations, retours à la ligne…) devient un seul « _ ».
      .replace(/\s+/g, '_')
      .slice(0, NOM_VLAN_LONGUEUR_MAX)
  );
}

/**
 * Transforme le résultat de planVlsm() en liste de VLAN pour genererConfigurations().
 * choix : un élément par sous-réseau du plan, dans le même ordre : { id, ports },
 * ou null pour ne pas faire de VLAN avec ce sous-réseau (ex. un lien WAN entre deux routeurs).
 */
export function depuisPlanVlsm(plan, choix) {
  const sousReseaux = plan?.subnets;
  if (!Array.isArray(sousReseaux)) throw new Error('Plan VLSM invalide : utilise le résultat de planVlsm().');
  if (!Array.isArray(choix) || choix.length !== sousReseaux.length) {
    throw new Error(`Choix des VLAN : il en faut un par sous-réseau du plan (${sousReseaux.length} attendus).`);
  }
  const vlans = [];
  sousReseaux.forEach((sousReseau, i) => {
    const choixVlan = choix[i];
    // null : sous-réseau volontairement laissé de côté.
    if (choixVlan === null) return;
    if (typeof choixVlan !== 'object') throw new Error(`Choix n°${i + 1} : un objet { id, ports } ou null est attendu.`);
    vlans.push({
      id: choixVlan.id,
      // Nom vide (ex. un nom fait seulement d'emojis) : on se rabat sur « VLAN10 ».
      nom: nomVlanDepuis(sousReseau.name) || (Number.isInteger(choixVlan.id) ? `VLAN${choixVlan.id}` : ''),
      reseau: sousReseau.cidr,
      passerelle: sousReseau.gateway,
      ports: choixVlan.ports,
    });
  });
  // Pas de vérification ici : genererConfigurations() revérifie tout, y compris ce qui vient du plan.
  return vlans;
}
