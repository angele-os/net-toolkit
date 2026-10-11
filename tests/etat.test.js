// Tests du lien partageable (js/etat.js). Lancer avec : npm test
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { lireEtat, ecrireEtat, LONGUEUR_MAX_FRAGMENT } from '../js/etat.js';

const PLAN_TD = {
  onglet: 'vlsm',
  reseau: '192.168.10.0/24',
  besoins: [
    { nom: 'Admin', hotes: 100 },
    { nom: 'Prod', hotes: 50 },
    { nom: 'Wifi', hotes: 20 },
    { nom: 'Lien routeurs', hotes: 2 },
  ],
};

describe('ecrireEtat', () => {
  test('onglet IP : fragment lisible', () => {
    assert.equal(ecrireEtat({ onglet: 'ip', adresse: '192.168.1.37/27' }), 'ip=192.168.1.37/27');
  });

  test('onglet VLSM : nom et hotes répétés pour chaque besoin', () => {
    assert.equal(
      ecrireEtat(PLAN_TD),
      'vlsm=192.168.10.0/24&nom=Admin&hotes=100&nom=Prod&hotes=50&nom=Wifi&hotes=20&nom=Lien+routeurs&hotes=2',
    );
  });
});

describe('lireEtat : liens valides', () => {
  test('fragment vide → null (rien à restaurer)', () => {
    assert.equal(lireEtat(''), null);
    assert.equal(lireEtat('#'), null);
  });

  test('lit un lien IP, avec ou sans #', () => {
    assert.deepEqual(lireEtat('#ip=192.168.1.37/27'), { onglet: 'ip', adresse: '192.168.1.37/27' });
    assert.deepEqual(lireEtat('ip=192.168.1.37%2F27'), { onglet: 'ip', adresse: '192.168.1.37/27' });
  });

  test('accepte la notation avec masque', () => {
    assert.deepEqual(lireEtat('#ip=10.0.0.1+255.0.0.0'), { onglet: 'ip', adresse: '10.0.0.1 255.0.0.0' });
  });

  test('aller-retour : lire(écrire(plan)) redonne le plan', () => {
    assert.deepEqual(lireEtat(`#${ecrireEtat(PLAN_TD)}`), PLAN_TD);
  });

  test('aller-retour avec des caractères spéciaux dans les noms', () => {
    const plan = {
      onglet: 'vlsm',
      reseau: '10.0.0.0/16',
      besoins: ['Réseau élèves', 'R&D', 'a=b', 'Salle #2', '100 %', 'x+y', 'A/B', '📡 Antennes'].map((nom) => ({ nom, hotes: 10 })),
    };
    assert.deepEqual(lireEtat(`#${ecrireEtat(plan)}`), plan);
  });

  test('ignore les paramètres inconnus', () => {
    assert.deepEqual(lireEtat('#ip=10.0.0.1/8&pub=xyz'), { onglet: 'ip', adresse: '10.0.0.1/8' });
  });

  test('du HTML dans un nom reste du texte brut (c’est l’affichage par textContent qui le neutralise)', () => {
    const etat = lireEtat('#vlsm=10.0.0.0/24&nom=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E&hotes=2');
    assert.equal(etat.besoins[0].nom, '<img src=x onerror=alert(1)>');
  });
});

describe('lireEtat : liens piégés ou abîmés', () => {
  test('refuse un fragment trop long, vite et sans le recopier', () => {
    const enorme = `#ip=${'A'.repeat(LONGUEUR_MAX_FRAGMENT)}`;
    assert.throws(() => lireEtat(enorme), (e) => /Lien trop long/.test(e.message) && e.message.length < 120);
  });

  test('accepte un plan de 256 besoins aux noms les plus longs (la limite n’est pas trop basse)', () => {
    const plan = {
      onglet: 'vlsm',
      reseau: '10.0.0.0/8',
      // « € » prend 9 caractères une fois encodé : c'est le pire cas prévu.
      besoins: Array.from({ length: 256 }, () => ({ nom: '€'.repeat(32), hotes: 9_999_999_999 })),
    };
    const fragment = ecrireEtat(plan);
    assert.ok(fragment.length <= LONGUEUR_MAX_FRAGMENT, `${fragment.length} > ${LONGUEUR_MAX_FRAGMENT}`);
    assert.equal(lireEtat(fragment).besoins.length, 256);
  });

  test('refuse « ip » et « vlsm » ensemble, ou un mode répété, ou aucun mode', () => {
    for (const f of ['#ip=10.0.0.1/8&vlsm=10.0.0.0/8', '#ip=10.0.0.1/8&ip=8.8.8.8/32', '#nom=a&hotes=2', '#n%27importe%20quoi']) {
      assert.throws(() => lireEtat(f), /soit « ip », soit « vlsm »/, f);
    }
  });

  test('refuse une adresse invalide avec le message des champs', () => {
    assert.throws(() => lireEtat('#ip=999.1.1.1/24'), /dépasse 255/);
    assert.throws(() => lireEtat(`#ip=${'1'.repeat(41)}`), /Adresse trop longue/);
    assert.throws(() => lireEtat('#vlsm=10.0.0.0/33&nom=A&hotes=2'), /Préfixe invalide/);
  });

  test('ne plante pas sur un encodage % invalide', () => {
    // decodeURIComponent lèverait URIError ici ; URLSearchParams lit le texte tel quel.
    assert.throws(() => lireEtat('#ip=%E0%A4%A'), (e) => e instanceof Error && !(e instanceof URIError));
  });

  test('refuse des besoins incomplets ou absents', () => {
    assert.throws(() => lireEtat('#vlsm=10.0.0.0/24&nom=A&nom=B&hotes=2'), /un « nom » et un nombre/);
    assert.throws(() => lireEtat('#vlsm=10.0.0.0/24'), /aucun besoin/);
  });

  test('refuse plus de 256 besoins', () => {
    const fragment = `vlsm=10.0.0.0/8${'&nom=a&hotes=2'.repeat(257)}`;
    assert.throws(() => lireEtat(fragment), /256 besoins au maximum \(257 dans le lien\)/);
  });

  test('applique les règles des noms : vide, trop long, caractère invisible', () => {
    assert.throws(() => lireEtat('#vlsm=10.0.0.0/24&nom=&hotes=2'), /besoin n°1 : le nom est vide/);
    assert.throws(() => lireEtat(`#vlsm=10.0.0.0/24&nom=${'a'.repeat(33)}&hotes=2`), /dépasse 32/);
    // %E2%80%AE = U+202E (inversion du sens du texte)
    assert.throws(() => lireEtat('#vlsm=10.0.0.0/24&nom=Admin%E2%80%AEtxt&hotes=2'), /U\+202E/);
  });

  test('n’accepte que des chiffres pour les hôtes', () => {
    for (const hotes of ['', '1e3', '-5', '0x10', '2.5', '12345678901', '١٢']) {
      assert.throws(() => lireEtat(`#vlsm=10.0.0.0/24&nom=A&hotes=${encodeURIComponent(hotes)}`), /hôtes/, hotes);
    }
    assert.throws(() => lireEtat('#vlsm=10.0.0.0/24&nom=A&hotes=0'), /au moins 1/);
  });

  test('refuse ce qui n’est pas du texte', () => {
    assert.throws(() => lireEtat(undefined), TypeError);
  });
});
