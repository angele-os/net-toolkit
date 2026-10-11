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

/**
 * Vérifie la liste des besoins et lève une erreur claire au premier problème.
 */
function verifierBesoins(besoins) {
  if (!Array.isArray(besoins) || besoins.length === 0) {
    throw new Error('Aucun besoin : ajoute au moins un sous-réseau avec un nom et un nombre d’hôtes.');
  }
  besoins.forEach((besoin, i) => {
    // Numéro « humain » du besoin (on commence à 1) pour les messages d'erreur.
    const numero = i + 1;
    if (typeof besoin?.nom !== 'string' || besoin.nom.trim() === '') {
      throw new Error(`Besoin n°${numero} : le nom est vide.`);
    }
    if (!Number.isInteger(besoin.hotes) || besoin.hotes < 1) {
      throw new Error(`Besoin « ${besoin.nom} » : le nombre d’hôtes doit être un entier d’au moins 1 (reçu : ${besoin.hotes}).`);
    }
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
