// Tests de configuration des pages et du code source : limites de saisie, CSP, référencement,
// caractères invisibles. On lit les fichiers comme du texte : pas besoin de navigateur.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { LONGUEUR_MAX_ADRESSE } from '../js/ip.js';
import { NOM_LONGUEUR_MAX, HOTES_MAX } from '../js/vlsm.js';
import {
  HOSTNAME_LONGUEUR_MAX,
  NOM_VLAN_LONGUEUR_MAX,
  DOMAINE_LONGUEUR_MAX,
  BANNIERE_LONGUEUR_MAX,
  PLAGE_LONGUEUR_MAX,
  MAC_PAR_PORT_MAX,
  MARQUEUR,
} from '../js/cisco.js';

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

test('générateur Cisco : les maxlength correspondent aux limites de cisco.js', () => {
  const attendus = {
    'id="cisco-hostname-switch"': HOSTNAME_LONGUEUR_MAX,
    'id="cisco-hostname-routeur"': HOSTNAME_LONGUEUR_MAX,
    'id="cisco-trunk"': PLAGE_LONGUEUR_MAX,
    'js-vlan-ports': PLAGE_LONGUEUR_MAX,
    'id="cisco-domaine"': DOMAINE_LONGUEUR_MAX,
    'js-vlan-nom': NOM_VLAN_LONGUEUR_MAX,
    'id="cisco-natif-nom"': NOM_VLAN_LONGUEUR_MAX,
    'id="cisco-mgmt-nom"': NOM_VLAN_LONGUEUR_MAX,
    'id="cisco-mgmt-reseau"': LONGUEUR_MAX_ADRESSE,
    'id="cisco-dns"': LONGUEUR_MAX_ADRESSE,
    'id="cisco-banniere"': BANNIERE_LONGUEUR_MAX,
    // Numéros de VLAN : 4 chiffres (4094) ; adresses MAC par port : 2 chiffres (64).
    'js-vlan-id': String(4094).length,
    'id="cisco-natif-id"': String(4094).length,
    'id="cisco-mgmt-id"': String(4094).length,
    'id="cisco-ps-max"': String(MAC_PAR_PORT_MAX).length,
  };
  for (const [repere, limite] of Object.entries(attendus)) assert.equal(maxlength(repere), limite, repere);
});

describe('générateur Cisco : page', () => {
  test('trois onglets, chacun relié à son panneau', () => {
    const onglets = [...html.matchAll(/role="tab" id="([\w-]+)" aria-controls="([\w-]+)"/g)];
    assert.deepEqual(onglets.map((o) => o[1]), ['tab-ip', 'tab-vlsm', 'tab-cisco']);
    for (const [, onglet, panneau] of onglets) {
      assert.match(html, new RegExp(`id="${panneau}" role="tabpanel" aria-labelledby="${onglet}"`));
    }
  });

  test('l’avertissement « à relire et à tester » est présent, avec le marqueur à remplacer', () => {
    // Dans le HTML, < et > du marqueur s'écrivent &lt; et &gt;.
    const marqueur = MARQUEUR.replace('<', '&lt;').replace('>', '&gt;');
    assert.ok(
      html.includes(
        'Configuration à relire et à tester (par exemple dans Packet Tracer) avant tout usage sur un équipement réel.',
      ),
    );
    assert.ok(html.includes(`Remplace les marqueurs <code>${marqueur}</code>.`));
  });

  test('le bouton d’envoi depuis le plan VLSM existe', () => {
    assert.match(html, /id="btn-envoyer-cisco"[\s\S]*?Envoyer vers le générateur Cisco/);
  });

  test('chaque bouton Copier ou Télécharger des configurations vise le switch ou le routeur', () => {
    const cibles = [...html.matchAll(/class="[^"]*\b(btn-copy|btn-txt)\b[^"]*" type="button" data-config="(\w+)"/g)];
    assert.deepEqual(cibles.map((c) => `${c[1]}:${c[2]}`), ['btn-copy:switch', 'btn-txt:switch', 'btn-copy:routeur', 'btn-txt:routeur']);
  });
});

test('style.css : l’attribut hidden cache toujours l’élément, même avec un display: grid', () => {
  assert.match(lire('css/style.css'), /\[hidden\]\s*\{\s*display:\s*none\s*!important;\s*\}/);
});

test('aucun code JavaScript n’écrit du HTML (innerHTML, outerHTML, insertAdjacentHTML, document.write)', () => {
  for (const fichier of readdirSync(new URL('../js/', import.meta.url))) {
    // On cherche l'UTILISATION (affectation ou appel), pas le mot : les commentaires disent « jamais d'innerHTML ».
    assert.doesNotMatch(
      lire(`js/${fichier}`),
      /\.(innerHTML|outerHTML)\s*\+?=|insertAdjacentHTML\s*\(|document\.write(ln)?\s*\(/,
      `js/${fichier}`,
    );
  }
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

test('la page ignore l’adresse : aucun code ne lit ni n’écrit location, le # ou l’historique', () => {
  // Le lien partageable a été retiré pour réduire la surface d'attaque : aucune donnée extérieure
  // ne doit entrer dans la page par l'adresse. Ce test empêche de la réintroduire par accident.
  for (const fichier of readdirSync(new URL('../js/', import.meta.url))) {
    const code = lire(`js/${fichier}`);
    assert.doesNotMatch(code, /\blocation\b|\.hash\b|hashchange|\bhistory\b|replaceState|pushState|URLSearchParams/, `js/${fichier}`);
  }
});

// Fichiers d'un dossier ET de ses sous-dossiers (ex. tests/fixtures/), sans les dossiers eux-mêmes
// ni les fichiers cachés (ex. .DS_Store créé par le Finder de macOS).
function fichiersDe(dossier) {
  return readdirSync(new URL(`../${dossier}/`, import.meta.url), { recursive: true })
    .map((chemin) => `${dossier}/${chemin}`)
    .filter((chemin) => !chemin.split('/').at(-1).startsWith('.'))
    .filter((chemin) => statSync(new URL(`../${chemin}`, import.meta.url)).isFile());
}

test('aucun caractère invisible ou de contrôle dans le code source (Trojan Source)', () => {
  const fichiers = ['index.html', '404.html', 'css/style.css', ...fichiersDe('js'), ...fichiersDe('tests')];
  for (const fichier of fichiers) {
    lire(fichier).split('\n').forEach((ligne, i) => {
      // Cf (mise en forme invisible) ou Cc (contrôle) sauf la tabulation et le retour chariot.
      const trouve = ligne.match(/[\p{Cf}]|[\p{Cc}--[\t\r]]/v);
      assert.equal(trouve, null, `${fichier}:${i + 1} contient U+${trouve?.[0].codePointAt(0).toString(16).toUpperCase().padStart(4, '0')}`);
    });
  }
});
