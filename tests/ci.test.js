// Tests de configuration de l'intégration continue (.github/workflows/). Lancer avec : npm test
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';

const dossier = new URL('../.github/workflows/', import.meta.url);
const workflows = readdirSync(dossier).map((nom) => ({ nom, texte: readFileSync(new URL(nom, dossier), 'utf8') }));

test('toutes les actions sont épinglées par une empreinte SHA complète, avec la version en commentaire', () => {
  for (const { nom, texte } of workflows) {
    const lignes = texte.split('\n').filter((ligne) => /^\s*(-\s*)?uses:/.test(ligne));
    assert.ok(lignes.length > 0, `${nom} : aucune action trouvée`);
    for (const ligne of lignes) {
      // Ex. « uses: actions/checkout@3d3c42e5…ba90b1 # v7.0.1 » : 40 caractères hexadécimaux, puis « # vX.Y.Z ».
      assert.match(ligne, /uses: [\w.-]+\/[\w.-]+@[0-9a-f]{40} # v\d+\.\d+\.\d+\s*$/, `${nom} : ${ligne.trim()}`);
    }
  }
});

test('le déploiement ne publie que les fichiers du site, après les tests', () => {
  const deploy = workflows.find((w) => w.nom === 'deploy.yml')?.texte;
  assert.ok(deploy, 'deploy.yml absent');
  // Liste blanche exacte des fichiers copiés dans _site.
  assert.match(deploy, /cp index\.html 404\.html favicon\.svg robots\.txt sitemap\.xml _site\/\n\s*cp -R css js fonts _site\//);
  // Le job deploy attend les tests et la construction.
  assert.match(deploy, /deploy:[\s\S]*needs: \[test, build\]/);
  // Les droits d'écriture n'apparaissent qu'une fois (dans le job deploy).
  assert.equal(deploy.match(/pages: write/g)?.length, 1);
  assert.equal(deploy.match(/id-token: write/g)?.length, 1);
});
