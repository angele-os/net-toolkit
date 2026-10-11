// État partageable dans l'adresse de la page, après le # (le « fragment ») : fonctions pures,
// testées dans tests/etat.test.js.
//
// Exemples :
//   #ip=192.168.1.37/27
//   #vlsm=192.168.10.0/24&nom=Admin&hotes=100&nom=Prod&hotes=50
//
// SÉCURITÉ : le fragment est une donnée NON FIABLE. N'importe qui peut fabriquer un lien
// et l'envoyer à une victime. On le lit donc comme une saisie au clavier :
// longueur limitée, découpage par URLSearchParams, validation par les MÊMES fonctions et
// limites que les champs du formulaire. Le résultat ne contient que des chaînes et des nombres
// vérifiés ; l'interface les affiche uniquement avec .value et textContent.
import { parseCidr } from './ip.js';
import { erreurNom, erreurHotes, BESOINS_MAX, NOM_LONGUEUR_MAX } from './vlsm.js';

// Longueur maximale du fragment, déduite des limites de saisie :
// un caractère d'un nom peut prendre jusqu'à 9 caractères une fois encodé (« é » → « %C3%A9 » en fait 6,
// un caractère sur 3 octets comme « € » → « %E2%82%AC » en fait 9), plus « &nom=…&hotes=9999999999 » (≈ 30).
// 256 besoins × (32 × 9 + 40) + 200 pour le réseau ≈ 84 000 caractères.
export const LONGUEUR_MAX_FRAGMENT = 200 + BESOINS_MAX * (NOM_LONGUEUR_MAX * 9 + 40);

/**
 * Lit le fragment (avec ou sans « # »). Renvoie :
 *   null                                       si le fragment est vide (rien à restaurer) ;
 *   { onglet: 'ip', adresse }                  pour l'onglet « Analyser une IP » ;
 *   { onglet: 'vlsm', reseau, besoins: [{ nom, hotes }] } pour l'onglet VLSM.
 * Lève une Error au message clair si le fragment est invalide.
 */
export function lireEtat(fragment) {
  if (typeof fragment !== 'string') throw new TypeError('Lien invalide : texte attendu.');
  // On retire le « # » du début s'il est présent.
  const brut = fragment.startsWith('#') ? fragment.slice(1) : fragment;
  if (brut === '') return null;

  // 1. Longueur vérifiée AVANT toute lecture, et le texte n'est pas recopié dans le message.
  if (brut.length > LONGUEUR_MAX_FRAGMENT) {
    throw new Error(`Lien trop long : ${LONGUEUR_MAX_FRAGMENT} caractères au maximum après le #.`);
  }

  // 2. Découpage par URLSearchParams : il gère le décodage (%2F, +…) et ne plante pas
  //    sur un encodage invalide (contrairement à decodeURIComponent, qui lève URIError).
  const params = new URLSearchParams(brut);
  const ip = params.getAll('ip');
  const vlsm = params.getAll('vlsm');

  // 3. Exactement un mode, une seule fois (refuse « ip » + « vlsm », ou « ip » répété).
  if (ip.length + vlsm.length !== 1) {
    throw new Error('Lien invalide : il doit contenir soit « ip », soit « vlsm », une seule fois.');
  }

  // 4. Validation par les mêmes fonctions que le formulaire.
  if (ip.length === 1) {
    // parseCidr applique la limite de 40 caractères et lève une erreur claire si l'adresse est invalide.
    parseCidr(ip[0]);
    return { onglet: 'ip', adresse: ip[0].trim() };
  }

  const reseau = vlsm[0];
  parseCidr(reseau);
  const noms = params.getAll('nom');
  const hotes = params.getAll('hotes');
  if (noms.length !== hotes.length) {
    throw new Error('Lien invalide : chaque besoin doit avoir un « nom » et un nombre d’« hotes ».');
  }
  if (noms.length === 0) throw new Error('Lien invalide : aucun besoin.');
  if (noms.length > BESOINS_MAX) {
    throw new Error(`Lien invalide : ${BESOINS_MAX} besoins au maximum (${noms.length} dans le lien).`);
  }

  const besoins = noms.map((nom, i) => {
    const numero = i + 1;
    const erreur = erreurNom(nom);
    if (erreur) throw new Error(`Lien invalide : besoin n°${numero} : ${erreur}`);
    // Le nombre d'hôtes arrive en texte : 1 à 10 chiffres, rien d'autre (refuse « 1e3 », « -5 », « 0x10 »…).
    if (!/^\d{1,10}$/.test(hotes[i])) {
      throw new Error(`Lien invalide : besoin n°${numero} : le nombre d’hôtes doit être un entier de 1 à 10 chiffres.`);
    }
    const nombre = Number(hotes[i]);
    const erreurNombre = erreurHotes(nombre);
    if (erreurNombre) throw new Error(`Lien invalide : besoin n°${numero} : ${erreurNombre}`);
    return { nom: nom.trim(), hotes: nombre };
  });

  return { onglet: 'vlsm', reseau: reseau.trim(), besoins };
}

/**
 * Écrit l'état sous forme de fragment (sans le « # »).
 */
export function ecrireEtat(etat) {
  const params = new URLSearchParams();
  if (etat.onglet === 'ip') {
    params.set('ip', etat.adresse);
  } else {
    params.set('vlsm', etat.reseau);
    // append (et non set) : les clés « nom » et « hotes » sont répétées, une fois par besoin.
    for (const besoin of etat.besoins) {
      params.append('nom', besoin.nom);
      params.append('hotes', String(besoin.hotes));
    }
  }
  // URLSearchParams encode « / » en « %2F » ; le « / » est autorisé après le #, on le garde lisible.
  return params.toString().replaceAll('%2F', '/');
}
