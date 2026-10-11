// Tests de configuration de index.html : limites de saisie et en-tête de sécurité (CSP).
// On lit le fichier comme du texte : pas besoin de navigateur.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { LONGUEUR_MAX_ADRESSE } from '../js/ip.js';
import { NOM_LONGUEUR_MAX, HOTES_MAX } from '../js/vlsm.js';

const html = readFileSync(new URL('../index.html', import.meta.url), 'utf8');

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

test('la CSP contient toutes les protections attendues', () => {
  const csp = html.match(/http-equiv="Content-Security-Policy" content="([^"]+)"/)?.[1];
  assert.ok(csp, 'balise CSP absente');
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
    assert.ok(csp.split(';').map((d) => d.trim()).includes(directive), `directive manquante : ${directive}`);
  }
  // Aucune source dangereuse ne doit apparaître.
  assert.doesNotMatch(csp, /unsafe-inline|unsafe-eval|data:|\*/);
});

test('aucun script, style ou gestionnaire d’événement en ligne', () => {
  // Les seuls <script> autorisés pointent vers un fichier (src=…).
  assert.doesNotMatch(html, /<script(?![^>]*\bsrc=)[^>]*>/);
  assert.doesNotMatch(html, /<style\b/);
  assert.doesNotMatch(html, /\sstyle="/);
  assert.doesNotMatch(html, /\son[a-z]+="/);
});

test('la balise CSP est placée avant toute ressource', () => {
  const positionCsp = html.indexOf('Content-Security-Policy');
  for (const ressource of ['<link', '<script']) {
    assert.ok(positionCsp < html.indexOf(ressource), `la CSP doit précéder ${ressource}`);
  }
});
