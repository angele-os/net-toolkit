// Mise en forme des exports (copie et CSV) : fonctions pures, testées dans tests/export.test.js.
// Les données à exporter ont la forme { entetes: string[], lignes: string[][] }.

/**
 * Protection contre l'« injection CSV » (ou injection de formule, recommandations OWASP).
 * Un tableur (Excel, LibreOffice) exécute comme une formule une cellule qui commence par
 * = + - @, ou par une tabulation ou un retour chariot suivis d'une formule.
 * On préfixe ces cellules d'une apostrophe : le tableur les affiche alors comme du texte.
 * Ex. un besoin nommé « =HYPERLINK("http://pirate.example";"Clique") » reste inoffensif.
 */
export function celluleSure(valeur) {
  const texte = String(valeur);
  return /^[=+\-@\t\r]/.test(texte) ? `'${texte}` : texte;
}

/**
 * Texte pour le presse-papiers : cellules séparées par des tabulations, lignes par des retours à la ligne.
 * Collé dans un tableur, chaque valeur va dans sa colonne.
 */
export function versTexteTabule({ entetes, lignes }) {
  return [entetes, ...lignes]
    // Une tabulation ou un retour à la ligne DANS une cellule casserait les colonnes : on les remplace par un espace.
    .map((ligne) => ligne.map((c) => celluleSure(c).replace(/[\t\r\n]+/g, ' ')).join('\t'))
    .join('\n');
}

/**
 * CSV avec « ; » comme séparateur (Excel en français utilise la virgule pour les décimales).
 * Fins de ligne \r\n, comme le prévoit la RFC 4180 qui décrit le format CSV.
 */
export function versCsv({ entetes, lignes }) {
  const cellule = (valeur) => {
    const texte = celluleSure(valeur);
    // Si la cellule contient ; " ou un retour à la ligne, on l'entoure de guillemets et on double les ".
    // Sans ça, « a;=1+1 » serait coupé en deux cellules, et la 2e (« =1+1 ») serait une formule.
    return /[";\r\n]/.test(texte) ? `"${texte.replaceAll('"', '""')}"` : texte;
  };
  return [entetes, ...lignes].map((ligne) => ligne.map(cellule).join(';')).join('\r\n');
}
