// Tests du calcul VLSM (js/vlsm.js). Lancer avec : npm test
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { planVlsm, erreurNom, erreurHotes, NOM_LONGUEUR_MAX, HOTES_MAX, BESOINS_MAX } from '../js/vlsm.js';

// Besoins du cas de référence (TD classique).
const BESOINS_REFERENCE = [
  { nom: 'Admin', hotes: 100 },
  { nom: 'Prod', hotes: 50 },
  { nom: 'Wifi', hotes: 20 },
  { nom: 'Lien', hotes: 2 },
];

describe('planVlsm : cas de référence 192.168.10.0/24', () => {
  const plan = planVlsm('192.168.10.0/24', BESOINS_REFERENCE);

  test('place les blocs du plus grand au plus petit', () => {
    assert.deepEqual(
      plan.subnets.map((s) => s.cidr),
      ['192.168.10.0/25', '192.168.10.128/26', '192.168.10.192/27', '192.168.10.224/30'],
    );
    assert.deepEqual(plan.subnets.map((s) => s.name), ['Admin', 'Prod', 'Wifi', 'Lien']);
  });

  test('détaille chaque sous-réseau', () => {
    const prod = plan.subnets[1];
    assert.equal(prod.requestedHosts, 50);
    assert.equal(prod.mask, '255.255.255.192');
    assert.equal(prod.gateway, '192.168.10.129');
    assert.equal(prod.firstHost, '192.168.10.129');
    assert.equal(prod.lastHost, '192.168.10.190');
    assert.equal(prod.broadcast, '192.168.10.191');
    assert.equal(prod.usableHosts, 62);
  });

  test('calcule le taux d’utilisation', () => {
    assert.equal(plan.subnets[0].usage, 79.4); // 100 / 126
    assert.equal(plan.subnets[3].usage, 100); // 2 / 2
  });

  test('renvoie l’espace libre à partir de .228', () => {
    assert.deepEqual(plan.free, {
      start: '192.168.10.228',
      end: '192.168.10.255',
      addresses: 28,
      blocks: ['192.168.10.228/30', '192.168.10.232/29', '192.168.10.240/28'],
    });
  });
});

describe('planVlsm : autres cas', () => {
  test('même résultat si les besoins sont dans le désordre', () => {
    const desordre = [BESOINS_REFERENCE[3], BESOINS_REFERENCE[0], BESOINS_REFERENCE[2], BESOINS_REFERENCE[1]];
    assert.deepEqual(planVlsm('192.168.10.0/24', desordre), planVlsm('192.168.10.0/24', BESOINS_REFERENCE));
  });

  test('frontières des puissances de 2 : 62 hôtes → /26, 63 hôtes → /25', () => {
    assert.equal(planVlsm('10.0.0.0/24', [{ nom: 'A', hotes: 62 }]).subnets[0].prefix, 26);
    assert.equal(planVlsm('10.0.0.0/24', [{ nom: 'A', hotes: 63 }]).subnets[0].prefix, 25);
  });

  test('plan qui remplit exactement le réseau : pas d’espace libre', () => {
    const plan = planVlsm('10.0.0.0/24', [
      { nom: 'A', hotes: 126 },
      { nom: 'B', hotes: 126 },
    ]);
    assert.deepEqual(plan.subnets.map((s) => s.cidr), ['10.0.0.0/25', '10.0.0.128/25']);
    assert.equal(plan.free, null);
  });

  test('accepte la notation avec masque', () => {
    assert.deepEqual(
      planVlsm('192.168.10.0 255.255.255.0', BESOINS_REFERENCE),
      planVlsm('192.168.10.0/24', BESOINS_REFERENCE),
    );
  });
});

describe('planVlsm : erreurs', () => {
  test('le plan ne rentre pas : indique combien il manque', () => {
    assert.throws(
      () => planVlsm('192.168.10.0/24', [{ nom: 'A', hotes: 200 }, { nom: 'B', hotes: 100 }]),
      /il manque 128 adresses/,
    );
  });

  test('refuse un nombre d’hôtes nul, négatif ou non entier', () => {
    for (const hotes of [0, -3, 2.5]) {
      assert.throws(() => planVlsm('10.0.0.0/24', [{ nom: 'A', hotes }]), /hôtes/);
    }
  });

  test('refuse un nom vide', () => {
    assert.throws(() => planVlsm('10.0.0.0/24', [{ nom: '', hotes: 10 }]), /nom est vide/);
    assert.throws(() => planVlsm('10.0.0.0/24', [{ nom: '   ', hotes: 10 }]), /nom est vide/);
  });

  test('refuse une liste de besoins vide', () => {
    assert.throws(() => planVlsm('10.0.0.0/24', []), /Aucun besoin/);
  });

  test('réseau mal aligné : propose la bonne adresse', () => {
    assert.throws(() => planVlsm('192.168.10.5/24', BESOINS_REFERENCE), /Voulais-tu dire 192\.168\.10\.0\/24/);
  });

  test('indique le numéro du besoin en cause', () => {
    assert.throws(
      () => planVlsm('10.0.0.0/24', [{ nom: 'A', hotes: 10 }, { nom: 'B', hotes: 0 }]),
      /^Error: Besoin n°2 : le nombre d’hôtes/,
    );
  });
});

describe('limites de saisie', () => {
  test('valeurs des limites', () => {
    assert.equal(NOM_LONGUEUR_MAX, 32);
    assert.equal(HOTES_MAX, 9_999_999_999);
    assert.equal(BESOINS_MAX, 256);
  });

  test('nom : 32 caractères acceptés, 33 refusés', () => {
    assert.equal(erreurNom('a'.repeat(32)), null);
    assert.match(erreurNom('a'.repeat(33)), /dépasse 32 caractères \(33 saisis\)/);
    // Les espaces autour ne comptent pas : le nom est utilisé sans eux.
    assert.equal(erreurNom(`  ${'a'.repeat(32)}  `), null);
  });

  test('hôtes : 10 chiffres acceptés, 11 refusés', () => {
    assert.equal(erreurHotes(9_999_999_999), null);
    assert.match(erreurHotes(10_000_000_000), /ne peut pas dépasser/);
  });

  test('besoins : 256 acceptés, 257 refusés', () => {
    // 256 besoins de 2 hôtes = 256 blocs /30 = 1024 adresses : ça tient pile dans un /22.
    const besoins = (n) => Array.from({ length: n }, (_, i) => ({ nom: `L${i + 1}`, hotes: 2 }));
    assert.equal(planVlsm('10.0.0.0/22', besoins(256)).subnets.length, 256);
    assert.throws(() => planVlsm('10.0.0.0/16', besoins(257)), /Trop de besoins : 256 au maximum \(257 reçus\)/);
  });

  test('planVlsm applique les limites même sans l’interface', () => {
    assert.throws(() => planVlsm('10.0.0.0/24', [{ nom: 'a'.repeat(33), hotes: 2 }]), /dépasse 32/);
    assert.throws(() => planVlsm('10.0.0.0/8', [{ nom: 'A', hotes: 10_000_000_000 }]), /ne peut pas dépasser/);
  });
});

describe('caractères invisibles et de contrôle dans les noms', () => {
  const interdits = {
    'U+202E (inversion du sens du texte, « Trojan Source »)': ['Admin\u202Etxt.exe', '202E'],
    'U+200B (espace sans chasse)': ['Ad​min', '200B'],
    'U+2066 (isolat gauche-à-droite)': ['\u2066Admin', '2066'],
    'U+FEFF (indicateur d’ordre des octets) au milieu': ['Ad﻿min', 'FEFF'],
    'U+0000 (caractère nul)': ['Ad\u0000min', '0000'],
    'U+0009 (tabulation) au milieu': ['Ad\tmin', '0009'],
    'U+001B (échappement)': ['Ad\u001B[31mmin', '001B'],
  };
  for (const [description, [nom, code]] of Object.entries(interdits)) {
    test(`refuse ${description}`, () => {
      assert.equal(erreurNom(nom), `le nom contient un caractère invisible ou de contrôle (U+${code}), non autorisé.`);
    });
  }

  test('le message ne recopie pas le caractère invisible', () => {
    assert.throws(
      () => planVlsm('10.0.0.0/24', [{ nom: 'Admin\u202Etxt.exe', hotes: 2 }]),
      (erreur) => !erreur.message.includes('\u202E') && erreur.message.includes('U+202E'),
    );
  });

  test('accepte les accents, espaces, tirets et emojis simples', () => {
    for (const nom of ['Salle B12', 'Réseau élèves', 'Wi-Fi invités', 'DMZ_1', '📡 Antennes']) {
      assert.equal(erreurNom(nom), null, nom);
    }
  });
});
