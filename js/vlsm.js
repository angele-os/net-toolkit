// Calcul VLSM (Variable Length Subnet Mask) : fonction pure, testée dans tests/vlsm.test.js.
// On réutilise les calculs IPv4 de ip.js au lieu de les refaire.
import { parseCidr, prefixToMask, ipToString, analyze } from './ip.js';

/**
 * Plus petite puissance de 2 capable de contenir « hotes » machines,
 * en comptant l'adresse réseau et le broadcast (+ 2).
 */
function tailleBloc(hotes) {
  // Il faut de la place pour les hôtes + l'adresse réseau + le broadcast.
  const besoin = hotes + 2;
  // On part du plus petit bloc possible (1 adresse)...
  let taille = 1;
  // ... et on double jusqu'à ce que ça suffise : 1, 2, 4, 8, 16, 32, 64, 128...
  while (taille < besoin) taille *= 2;
  return taille;
}

/**
 * Découpe une plage libre [debut, fin] en blocs CIDR alignés, du début vers la fin.
 * Ex. de .228 à .255 → .228/30, .232/29, .240/28.
 */
function decouperEnBlocs(debut, fin) {
  const blocs = [];
  // Curseur : première adresse pas encore couverte.
  let curseur = debut;
  while (curseur <= fin) {
    // Nombre d'adresses restant à couvrir.
    const reste = fin - curseur + 1;
    // On cherche le plus gros bloc qui commence pile sur le curseur (aligné) et qui ne dépasse pas.
    let taille = 1;
    // On double tant que le curseur reste un multiple du bloc double et que ça tient dans le reste.
    while (taille * 2 <= reste && curseur % (taille * 2) === 0) taille *= 2;
    // Préfixe du bloc : 32 bits moins le nombre de bits nécessaires pour « taille » adresses.
    const prefixe = 32 - Math.log2(taille);
    blocs.push(`${ipToString(curseur)}/${prefixe}`);
    // On avance juste après ce bloc.
    curseur += taille;
  }
  return blocs;
}

/* ---------- Limites de saisie (exportées : l'interface et les tests utilisent les mêmes valeurs) ---------- */

// Longueur maximale d'un nom de sous-réseau.
export const NOM_LONGUEUR_MAX = 32;
// Nombre d'hôtes maximal : 10 chiffres. Bien plus que les 2³² adresses IPv4, donc aucun plan réel n'est bloqué.
export const HOTES_MAX = 9_999_999_999;
// Nombre maximal de besoins dans un plan.
export const BESOINS_MAX = 256;

// Caractères interdits dans un nom : catégories Unicode Cc (contrôle : tabulation, retour chariot…)
// et Cf (mise en forme invisible : U+202E qui inverse le sens du texte, U+200B espace sans chasse…).
// Le drapeau « u » active les classes \p{…} (propriétés Unicode).
const CARACTERE_INVISIBLE = /[\p{Cc}\p{Cf}]/u;

/**
 * Vérifie un nom de besoin. Renvoie le message d'erreur (en minuscule), ou null si le nom est valide.
 */
export function erreurNom(nom) {
  if (typeof nom !== 'string' || nom.trim() === '') return 'le nom est vide.';
  // On vérifie le nom tel qu'il sera utilisé : sans espaces au début ni à la fin.
  const propre = nom.trim();
  if (propre.length > NOM_LONGUEUR_MAX) {
    return `le nom dépasse ${NOM_LONGUEUR_MAX} caractères (${propre.length} saisis).`;
  }
  const trouve = propre.match(CARACTERE_INVISIBLE);
  if (trouve) {
    // On n'affiche PAS le caractère lui-même (U+202E retournerait le message), mais son code : U+202E.
    const code = trouve[0].codePointAt(0).toString(16).toUpperCase().padStart(4, '0');
    return `le nom contient un caractère invisible ou de contrôle (U+${code}), non autorisé.`;
  }
  return null;
}

/**
 * Vérifie un nombre d'hôtes. Renvoie le message d'erreur (en minuscule), ou null s'il est valide.
 */
export function erreurHotes(hotes) {
  if (!Number.isInteger(hotes) || hotes < 1) return 'le nombre d’hôtes doit être un entier d’au moins 1.';
  if (hotes > HOTES_MAX) return `le nombre d’hôtes ne peut pas dépasser ${HOTES_MAX} (10 chiffres).`;
  return null;
}

/**
 * Vérifie la liste des besoins et lève une erreur claire au premier problème.
 */
function verifierBesoins(besoins) {
  if (!Array.isArray(besoins) || besoins.length === 0) {
    throw new Error('Aucun besoin : ajoute au moins un sous-réseau avec un nom et un nombre d’hôtes.');
  }
  if (besoins.length > BESOINS_MAX) {
    throw new Error(`Trop de besoins : ${BESOINS_MAX} au maximum (${besoins.length} reçus).`);
  }
  besoins.forEach((besoin, i) => {
    // Numéro « humain » du besoin (on commence à 1) pour les messages d'erreur.
    const numero = i + 1;
    // ?. : si « besoin » n'est pas un objet, on lit undefined au lieu de planter.
    const erreur = erreurNom(besoin?.nom) ?? erreurHotes(besoin?.hotes);
    if (erreur) throw new Error(`Besoin n°${numero} : ${erreur}`);
  });
}

/**
 * Calcule un plan d'adressage VLSM.
 * @param {string} reseau  ex. "192.168.10.0/24" ou "192.168.10.0 255.255.255.0"
 * @param {{nom: string, hotes: number}[]} besoins
 */
export function planVlsm(reseau, besoins) {
  // 1. Lecture du réseau de départ (accepte « /24 » ou un masque).
  const { ip, prefix } = parseCidr(reseau);
  // Masque du réseau de départ.
  const masque = prefixToMask(prefix);
  // Adresse réseau correcte : on efface la partie hôte avec un ET.
  const debutReseau = (ip & masque) >>> 0;
  // Si l'IP saisie n'est pas déjà l'adresse réseau, elle est mal alignée.
  if (debutReseau !== ip) {
    throw new Error(
      `${ipToString(ip)}/${prefix} n'est pas une adresse de réseau. Voulais-tu dire ${ipToString(debutReseau)}/${prefix} ?`,
    );
  }
  // Nombre total d'adresses dans le réseau : 2^(bits hôte).
  const tailleReseau = 2 ** (32 - prefix);
  // Dernière adresse du réseau (broadcast).
  const finReseau = debutReseau + tailleReseau - 1;

  // 2. Vérification des besoins.
  verifierBesoins(besoins);

  // 3. Taille de bloc pour chaque besoin (on garde l'ordre de saisie pour l'instant).
  const blocs = besoins.map((b) => ({ nom: b.nom.trim(), hotes: b.hotes, taille: tailleBloc(b.hotes) }));

  // 4. Est-ce que tout rentre ? On additionne toutes les tailles.
  const totalNecessaire = blocs.reduce((somme, b) => somme + b.taille, 0);
  if (totalNecessaire > tailleReseau) {
    // Différence entre ce qu'il faut et ce qu'on a.
    const manque = totalNecessaire - tailleReseau;
    throw new Error(
      `Le plan ne rentre pas dans ${ipToString(debutReseau)}/${prefix} : il manque ${manque} adresses ` +
        `(${totalNecessaire} nécessaires, ${tailleReseau} disponibles).`,
    );
  }

  // 5. Tri du plus grand bloc au plus petit (tri stable : à taille égale, l'ordre de saisie est gardé).
  blocs.sort((a, b) => b.taille - a.taille);

  // 6. Placement des blocs les uns à la suite des autres.
  // Curseur : prochaine adresse libre, on commence au début du réseau.
  let curseur = debutReseau;
  const subnets = blocs.map((bloc) => {
    // Préfixe du sous-réseau : 32 − nombre de bits hôte (log2 de la taille). Ex. 128 = 2^7 → /25.
    const prefixe = 32 - Math.log2(bloc.taille);
    // On réutilise analyze() de ip.js pour réseau, masque, plage et broadcast.
    const a = analyze(curseur, prefixe);
    // Adresses réellement utilisables par des machines : taille − réseau − broadcast.
    const utilisables = bloc.taille - 2;
    const sousReseau = {
      name: bloc.nom,
      requestedHosts: bloc.hotes,
      cidr: `${a.network}/${prefixe}`,
      network: a.network,
      prefix: prefixe,
      mask: a.mask,
      // Convention courante : la passerelle prend la première IP utilisable.
      gateway: a.firstHost,
      firstHost: a.firstHost,
      lastHost: a.lastHost,
      broadcast: a.broadcast,
      usableHosts: utilisables,
      // Taux d'utilisation en %, arrondi à 0,1 : ×1000, arrondi, ÷10.
      usage: Math.round((bloc.hotes / utilisables) * 1000) / 10,
    };
    // On avance le curseur juste après ce bloc.
    curseur += bloc.taille;
    return sousReseau;
  });

  // 7. Espace libre : de la prochaine adresse libre jusqu'à la fin du réseau.
  const free =
    curseur > finReseau
      ? null
      : {
          start: ipToString(curseur),
          end: ipToString(finReseau),
          // Nombre d'adresses libres (bornes incluses).
          addresses: finReseau - curseur + 1,
          blocks: decouperEnBlocs(curseur, finReseau),
        };

  return { network: `${ipToString(debutReseau)}/${prefix}`, subnets, free };
}
