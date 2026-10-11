// Tests du calcul VLSM (js/vlsm.js). Lancer avec : npm test
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { planVlsm } from '../js/vlsm.js';

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
});
