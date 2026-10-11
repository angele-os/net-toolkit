// Tests des exports (js/export.js). Lancer avec : npm test
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { celluleSure, versTexteTabule, versCsv } from '../js/export.js';

describe('celluleSure : protection contre l’injection CSV (OWASP)', () => {
  // Chaque caractère qu'un tableur interprète en début de cellule.
  const dangereux = {
    '=': '=1+1',
    '+': '+1+1',
    '-': '-1+1',
    '@': '@SUM(A1:A2)',
    tabulation: '\t=1+1',
    'retour chariot': '\r=1+1',
  };
  for (const [nom, valeur] of Object.entries(dangereux)) {
    test(`préfixe d’une apostrophe une cellule qui commence par ${nom}`, () => {
      assert.equal(celluleSure(valeur), `'${valeur}`);
    });
  }

  test('exemple réaliste : un lien piégé reste du texte', () => {
    const piege = '=HYPERLINK("http://pirate.example";"Clique ici")';
    assert.equal(celluleSure(piege), `'${piege}`);
  });

  test('laisse intactes les cellules normales', () => {
    for (const valeur of ['Admin', '192.168.10.0/25', '79,4', 'Lien = routeurs', '']) {
      assert.equal(celluleSure(valeur), valeur);
    }
  });

  test('accepte les nombres', () => {
    assert.equal(celluleSure(42), '42');
  });
});

describe('versCsv', () => {
  test('sépare par ; et termine les lignes par \\r\\n', () => {
    const csv = versCsv({ entetes: ['Nom', 'Hôtes'], lignes: [['Admin', '100'], ['Prod', '50']] });
    assert.equal(csv, 'Nom;Hôtes\r\nAdmin;100\r\nProd;50');
  });

  test('double les guillemets et entoure la cellule de guillemets', () => {
    const csv = versCsv({ entetes: ['Nom'], lignes: [['Salle "B12"']] });
    assert.equal(csv, 'Nom\r\n"Salle ""B12"""');
  });

  test('entoure de guillemets une cellule qui contient ;', () => {
    // Sans guillemets, « a;=1+1 » donnerait 2 cellules, et la 2e serait une formule.
    const csv = versCsv({ entetes: ['Nom'], lignes: [['a;=1+1']] });
    assert.equal(csv, 'Nom\r\n"a;=1+1"');
  });

  test('entoure de guillemets une cellule qui contient un retour à la ligne', () => {
    const csv = versCsv({ entetes: ['Nom'], lignes: [['ligne 1\nligne 2'], ['a\r\nb']] });
    assert.equal(csv, 'Nom\r\n"ligne 1\nligne 2"\r\n"a\r\nb"');
  });

  test('protège aussi contre les formules (apostrophe à l’intérieur des guillemets)', () => {
    const csv = versCsv({ entetes: ['Nom'], lignes: [['=1+1'], ['=A1;"x"']] });
    assert.equal(csv, `Nom\r\n'=1+1\r\n"'=A1;""x"""`);
  });
});

describe('versTexteTabule (copie)', () => {
  test('sépare les colonnes par des tabulations et les lignes par \\n', () => {
    const texte = versTexteTabule({ entetes: ['Nom', 'Hôtes'], lignes: [['Admin', '100']] });
    assert.equal(texte, 'Nom\tHôtes\nAdmin\t100');
  });

  test('remplace tabulations et retours à la ligne internes par un espace', () => {
    const texte = versTexteTabule({ entetes: ['Nom'], lignes: [['a\tb'], ['c\r\nd']] });
    assert.equal(texte, 'Nom\na b\nc d');
  });

  test('protège aussi contre les formules', () => {
    const texte = versTexteTabule({ entetes: ['Nom'], lignes: [['=1+1'], ['\t=1+1']] });
    assert.equal(texte, "Nom\n'=1+1\n' =1+1");
  });
});
