// Tests de configuration des pages et du code source : limites de saisie, CSP, référencement,
// caractères invisibles. On lit les fichiers comme du texte : pas besoin de navigateur.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { LONGUEUR_MAX_ADRESSE } from '../js/ip.js';
import { NOM_LONGUEUR_MAX, HOTES_MAX } from '../js/vlsm.js';

const lire = (chemin) => readFileSync(new URL(`../${chemin}`, import.meta.url), 'utf8');
const html = lire('index.html');
const PAGES = { 'index.html': html, '404.html': lire('404.html') };

// Renvoie la valeur de maxlength de la balise <input> qui contient « repere ».
function maxlength(repere) {
  const balise = html.match(new RegExp(`<input[^>]*${repere}[^>]*>`))?.[0];
  assert.ok(balise, `aucun <input> trouvé pour ${repere}`);
  return Number(balise.match(/maxlength="(\d+)"/)?.[1]);
}

test('les maxlength du HTML correspondent aux limites des fonctions pures', () => {
  assert.equal(maxlength('id="ip-input"'), LONGUEUR_MAX_ADRESSE);
  assert.equal(maxlength('id="vlsm-reseau"'), LONGUEUR_MAX_ADRESSE);
  assert.equal(maxlength('js-nom'), NOM_LONGUEUR_MAX);
  // 10 chiffres : la longueur du nombre maximal écrit en décimal.
  assert.equal(maxlength('js-hotes'), String(HOTES_MAX).length);
});

for (const [nom, page] of Object.entries(PAGES)) {
  describe(`sécurité de ${nom}`, () => {
    test('la CSP contient toutes les protections attendues', () => {
      const csp = page.match(/http-equiv="Content-Security-Policy" content="([^"]+)"/)?.[1];
      assert.ok(csp, 'balise CSP absente');
      const directives = csp.split(';').map((d) => d.trim());
      for (const directive of [
        "default-src 'none'",
        "script-src 'self'",
        "style-src 'self'",
        "img-src 'self'",
        "font-src 'self'",
        "object-src 'none'",
        "base-uri 'none'",
        "form-action 'none'",
        "require-trusted-types-for 'script'",
        "trusted-types 'none'",
        'upgrade-insecure-requests',
      ]) {
        assert.ok(directives.includes(directive), `directive manquante : ${directive}`);
      }
      // Aucune source dangereuse ne doit apparaître.
      assert.doesNotMatch(csp, /unsafe-inline|unsafe-eval|data:|\*/);
    });

    test('aucun script, style ou gestionnaire d’événement en ligne', () => {
      // Les seuls <script> autorisés pointent vers un fichier (src=…).
      assert.doesNotMatch(page, /<script(?![^>]*\bsrc=)[^>]*>/);
      assert.doesNotMatch(page, /<style\b/);
      assert.doesNotMatch(page, /\sstyle="/);
      assert.doesNotMatch(page, /\son[a-z]+="/);
    });

    test('la balise CSP est placée avant toute ressource', () => {
      const positionCsp = page.indexOf('Content-Security-Policy');
      for (const ressource of ['<link', '<script']) {
        const position = page.indexOf(ressource);
        if (position !== -1) assert.ok(positionCsp < position, `la CSP doit précéder ${ressource}`);
      }
    });
  });
}

describe('référencement', () => {
  const ADRESSE = 'https://reseau.ange-bonkoski.fr/';

  test('index.html : canonical et Open Graph', () => {
    assert.match(html, new RegExp(`<link rel="canonical" href="${ADRESSE}">`));
    for (const propriete of ['og:type', 'og:url', 'og:title', 'og:description', 'og:locale']) {
      assert.match(html, new RegExp(`<meta property="${propriete}" content="[^"]+">`), propriete);
    }
    assert.match(html, new RegExp(`<meta property="og:url" content="${ADRESSE}">`));
  });

  test('404.html : non indexée, liens absolus, retour vers l’accueil', () => {
    const page = PAGES['404.html'];
    assert.match(page, /<meta name="robots" content="noindex">/);
    assert.match(page, /href="\/css\/style\.css"/);
    assert.match(page, /<a [^>]*href="\/"/);
  });

  test('robots.txt et sitemap.xml pointent vers la bonne adresse', () => {
    assert.match(lire('robots.txt'), new RegExp(`Sitemap: ${ADRESSE}sitemap\\.xml`));
    assert.match(lire('sitemap.xml'), new RegExp(`<loc>${ADRESSE}</loc>`));
  });
});

test('aucun caractère invisible ou de contrôle dans le code source (Trojan Source)', () => {
  const fichiers = [
    'index.html', '404.html', 'css/style.css',
    ...readdirSync(new URL('../js/', import.meta.url)).map((f) => `js/${f}`),
    ...readdirSync(new URL('../tests/', import.meta.url)).map((f) => `tests/${f}`),
  ];
  for (const fichier of fichiers) {
    lire(fichier).split('\n').forEach((ligne, i) => {
      // Cf (mise en forme invisible) ou Cc (contrôle) sauf la tabulation et le retour chariot.
      const trouve = ligne.match(/[\p{Cf}]|[\p{Cc}--[\t\r]]/v);
      assert.equal(trouve, null, `${fichier}:${i + 1} contient U+${trouve?.[0].codePointAt(0).toString(16).toUpperCase().padStart(4, '0')}`);
    });
  }
});
