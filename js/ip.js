// Calculs IPv4 : fonctions pures (aucun accès à la page), testées dans tests/ip.test.js.
//
// Rappel important : en JavaScript, les opérateurs bit à bit (&, |, ~, <<) travaillent
// sur des entiers 32 bits SIGNÉS. Une adresse comme 255.255.255.255 ressortirait alors
// en -1. On ajoute donc « >>> 0 » après ces opérations : ce décalage de 0 bit ne change
// aucun bit, mais force JavaScript à relire le résultat comme un nombre positif (non signé).

// Un octet valide : « 0 » seul, ou 1 à 3 chiffres sans zéro en tête (refuse « 01 », « -4 », « »).
const OCTET = /^(0|[1-9]\d{0,2})$/;

// Plus grande valeur possible sur 32 bits : 2³² − 1 = 4294967295 (soit 255.255.255.255).
const MAX_IP = 0xFFFFFFFF;

/**
 * Convertit une IP écrite « 192.168.1.10 » en un entier 32 bits non signé.
 * Lève une erreur si le texte n'est pas une IPv4 valide.
 */
export function parseIp(texte) {
  // On n'accepte que du texte.
  if (typeof texte !== 'string') {
    throw new TypeError('IP invalide : une chaîne de caractères est attendue.');
  }
  // On découpe sur les points : "192.168.1.10" → ["192", "168", "1", "10"].
  const morceaux = texte.split('.');
  // Une IPv4 a exactement 4 octets.
  if (morceaux.length !== 4) {
    throw new Error(`IP invalide « ${texte} » : il faut exactement 4 nombres séparés par des points.`);
  }
  // Le résultat est construit octet par octet.
  let n = 0;
  for (const morceau of morceaux) {
    // Vérifie la forme : que des chiffres, sans zéro en tête.
    if (!OCTET.test(morceau)) {
      throw new Error(`IP invalide « ${texte} » : « ${morceau} » n'est pas un nombre valide (chiffres uniquement, sans zéro en tête).`);
    }
    // Convertit le texte en nombre.
    const octet = Number(morceau);
    // Un octet tient sur 8 bits : de 0 à 255.
    if (octet > 255) {
      throw new Error(`IP invalide « ${texte} » : ${octet} dépasse 255.`);
    }
    // Décale ce qu'on a déjà d'un octet vers la gauche (× 256) puis ajoute le nouvel octet.
    // On multiplie au lieu d'utiliser « << 8 » pour ne jamais tomber dans les nombres signés.
    n = n * 256 + octet;
  }
  return n;
}

/**
 * Convertit un entier 32 bits non signé en texte « a.b.c.d ».
 */
export function ipToString(n) {
  // On n'accepte qu'un entier entre 0 et 2³² − 1.
  if (!Number.isInteger(n) || n < 0 || n > MAX_IP) {
    throw new Error(`Entier IP invalide : ${n} (attendu un entier entre 0 et ${MAX_IP}).`);
  }
  return [
    // 1er octet : on décale de 24 bits vers la droite pour ne garder que les 8 bits du haut.
    n >>> 24,
    // 2e octet : décalage de 16 bits, puis « & 255 » garde seulement les 8 bits de droite.
    (n >>> 16) & 255,
    // 3e octet : même principe avec 8 bits.
    (n >>> 8) & 255,
    // 4e octet : les 8 bits de droite directement.
    n & 255,
  ].join('.');
}

/**
 * Convertit un préfixe (/24) en masque sous forme d'entier (255.255.255.0).
 */
export function prefixToMask(prefixe) {
  // Un préfixe est un entier de 0 à 32.
  if (!Number.isInteger(prefixe) || prefixe < 0 || prefixe > 32) {
    throw new Error(`Préfixe invalide : ${prefixe} (attendu un entier entre 0 et 32).`);
  }
  // Cas spécial /0 : en JavaScript, « x << 32 » vaut x (et non 0), donc on le traite à part.
  if (prefixe === 0) return 0;
  // On part de 32 bits à 1, on les pousse vers la gauche de (32 − préfixe) crans :
  // des 0 entrent par la droite. Ex. /27 → 5 zéros à droite → 11111111.11111111.11111111.11100000.
  // « >>> 0 » remet le résultat en non signé.
  return (MAX_IP << (32 - prefixe)) >>> 0;
}

/**
 * Convertit un masque (entier) en préfixe. Refuse les masques non contigus (ex. 255.0.255.0).
 */
export function maskToPrefix(masque) {
  // Le masque doit être un entier 32 bits non signé.
  if (!Number.isInteger(masque) || masque < 0 || masque > MAX_IP) {
    throw new Error(`Masque invalide : ${masque}.`);
  }
  // On compte les bits à 1 en partant de la gauche, jusqu'au premier 0.
  let prefixe = 0;
  // Le bit numéro (31 − prefixe) est lu en le décalant tout à droite puis en gardant le dernier bit.
  while (prefixe < 32 && ((masque >>> (31 - prefixe)) & 1) === 1) {
    prefixe++;
  }
  // Un vrai masque = des 1 puis uniquement des 0 : il doit être égal au masque reconstruit.
  if (prefixToMask(prefixe) !== masque) {
    throw new Error(`Masque invalide ${ipToString(masque)} : les bits à 1 doivent être contigus (ex. 255.255.255.224).`);
  }
  return prefixe;
}

/**
 * Lit « 192.168.1.37/27 » ou « 192.168.1.37 255.255.255.224 ».
 * Renvoie { ip, prefix } (ip en entier, prefix en nombre).
 */
export function parseCidr(texte) {
  // On n'accepte que du texte.
  if (typeof texte !== 'string') {
    throw new TypeError('Adresse invalide : une chaîne de caractères est attendue.');
  }
  // On retire les espaces au début et à la fin.
  const propre = texte.trim();

  // Forme « IP/préfixe ».
  if (propre.includes('/')) {
    // On sépare l'IP et le préfixe.
    const morceaux = propre.split('/');
    // Il faut exactement un « / ».
    if (morceaux.length !== 2) {
      throw new Error(`Format invalide « ${texte} » : un seul « / » est attendu.`);
    }
    const [ipTexte, prefixeTexte] = morceaux;
    // Le préfixe fait 1 ou 2 chiffres.
    if (!/^\d{1,2}$/.test(prefixeTexte)) {
      throw new Error(`Préfixe invalide « ${prefixeTexte} » : attendu un nombre entre 0 et 32.`);
    }
    const prefix = Number(prefixeTexte);
    // prefixToMask vérifie que le préfixe est bien entre 0 et 32.
    prefixToMask(prefix);
    return { ip: parseIp(ipTexte), prefix };
  }

  // Forme « IP masque » : on découpe sur un ou plusieurs espaces.
  const morceaux = propre.split(/\s+/);
  if (morceaux.length !== 2) {
    throw new Error(`Format invalide « ${texte} » : écris « 192.168.1.37/27 » ou « 192.168.1.37 255.255.255.224 ».`);
  }
  const [ipTexte, masqueTexte] = morceaux;
  // On lit le masque comme une IP, puis on le convertit en préfixe (refuse les masques non contigus).
  return { ip: parseIp(ipTexte), prefix: maskToPrefix(parseIp(masqueTexte)) };
}

// Plages d'adresses particulières : [réseau, préfixe, type]. La première qui correspond l'emporte.
const PLAGES = [
  ['127.0.0.0', 8, 'loopback'],      // RFC 1122 : la machine elle-même
  ['10.0.0.0', 8, 'private'],        // RFC 1918
  ['172.16.0.0', 12, 'private'],     // RFC 1918 (172.16.0.0 à 172.31.255.255)
  ['192.168.0.0', 16, 'private'],    // RFC 1918
  ['169.254.0.0', 16, 'link-local'], // RFC 3927 : adresse auto-attribuée sans DHCP
  ['224.0.0.0', 4, 'multicast'],     // RFC 5771 : classe D
  ['0.0.0.0', 8, 'reserved'],        // RFC 1122 : « ce réseau »
  ['240.0.0.0', 4, 'reserved'],      // RFC 1112 : classe E (inclut 255.255.255.255)
].map(([reseau, prefixe, type]) => ({ reseau: parseIp(reseau), masque: prefixToMask(prefixe), type }));

/**
 * Donne le type d'une adresse : private, public, loopback, link-local, multicast ou reserved.
 */
export function addressType(ip) {
  for (const plage of PLAGES) {
    // L'IP est dans la plage si, une fois masquée, elle donne l'adresse du réseau de la plage.
    if (((ip & plage.masque) >>> 0) === plage.reseau) return plage.type;
  }
  // Aucune plage spéciale : adresse publique.
  return 'public';
}

/**
 * Analyse complète d'une IP (entier) et d'un préfixe.
 */
export function analyze(ip, prefixe) {
  // Vérifie l'IP (lève une erreur si elle est invalide).
  ipToString(ip);
  // Masque : les bits à 1 désignent la partie réseau.
  const masque = prefixToMask(prefixe);
  // Wildcard : l'inverse du masque, les bits à 1 désignent la partie hôte.
  const wildcard = ~masque >>> 0;
  // Adresse réseau : IP ET masque, on garde la partie réseau et on met la partie hôte à 0.
  const reseau = (ip & masque) >>> 0;
  // Broadcast : réseau OU wildcard, on met toute la partie hôte à 1.
  const broadcast = (reseau | wildcard) >>> 0;

  let premiere, derniere, hotes;
  if (prefixe === 32) {
    // /32 : une seule adresse, l'hôte lui-même (ex. adresse de loopback d'un routeur).
    premiere = ip;
    derniere = ip;
    hotes = 1;
  } else if (prefixe === 31) {
    // /31 (RFC 3021) : liaison point à point, les 2 adresses sont utilisables.
    premiere = reseau;
    derniere = broadcast;
    hotes = 2;
  } else {
    // Cas général : on retire l'adresse réseau et le broadcast.
    premiere = reseau + 1;
    derniere = broadcast - 1;
    // 2^(bits hôte) − 2 ; on utilise ** et pas << pour supporter /0 (2³² ne tient pas dans un << ).
    hotes = 2 ** (32 - prefixe) - 2;
  }

  // IP en binaire : 32 caractères (zéros ajoutés à gauche), découpés en 4 groupes de 8.
  const binaire = ip.toString(2).padStart(32, '0').match(/.{8}/g).join('.');

  return {
    network: ipToString(reseau),
    broadcast: ipToString(broadcast),
    mask: ipToString(masque),
    wildcard: ipToString(wildcard),
    firstHost: ipToString(premiere),
    lastHost: ipToString(derniere),
    hosts: hotes,
    type: addressType(ip),
    binary: binaire,
  };
}
