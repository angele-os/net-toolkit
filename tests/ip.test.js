// Tests des calculs IPv4 (js/ip.js). Lancer avec : npm test
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import {
  parseIp,
  ipToString,
  prefixToMask,
  maskToPrefix,
  parseCidr,
  addressType,
  analyze,
  LONGUEUR_MAX_ADRESSE,
} from '../js/ip.js';

describe('limite de longueur des adresses', () => {
  test('vaut 40 caractères', () => {
    assert.equal(LONGUEUR_MAX_ADRESSE, 40);
  });

  test('accepte la forme la plus longue réellement utile (IP + masque)', () => {
    assert.deepEqual(parseCidr('255.255.255.255 255.255.255.255'), { ip: 4294967295, prefix: 32 });
  });

  test('accepte 40 caractères (espaces autour compris)', () => {
    const texte = `${'192.168.1.0/24'.padStart(27)}${' '.repeat(13)}`;
    assert.equal(texte.length, 40);
    assert.deepEqual(parseCidr(texte), parseCidr('192.168.1.0/24'));
  });

  test('refuse 41 caractères sans recopier le texte dans le message', () => {
    const texte = ' '.repeat(27) + '192.168.1.0/24';
    assert.equal(texte.length, 41);
    assert.throws(() => parseCidr(texte), /Adresse trop longue : 40 caractères au maximum \(41 saisis\)\.$/);
  });

  test('refuse un texte énorme rapidement, sans le recopier', () => {
    const enorme = '1.'.repeat(500_000);
    assert.throws(() => parseCidr(enorme), (erreur) => erreur.message.length < 100);
    assert.throws(() => parseIp(enorme), /trop longue/);
  });
});

describe('parseIp', () => {
  test('convertit une IP en entier', () => {
    assert.equal(parseIp('192.168.1.10'), 3232235786);
    assert.equal(parseIp('0.0.0.0'), 0);
  });

  test('reste non signé pour 255.255.255.255', () => {
    assert.equal(parseIp('255.255.255.255'), 4294967295);
  });

  test('refuse les IP invalides', () => {
    const invalides = [
      '256.1.1.1',  // octet > 255
      '1.2.3',      // 3 octets
      '1.2.3.4.5',  // 5 octets
      '01.2.3.4',   // zéro en tête
      '1.2.3.-4',   // signe
      '1..2.3',     // octet vide
      'a.b.c.d',    // pas des chiffres
      '',           // vide
      ' 1.2.3.4',   // espace
    ];
    for (const texte of invalides) {
      assert.throws(() => parseIp(texte), Error, `devrait refuser « ${texte} »`);
    }
    assert.throws(() => parseIp(42), TypeError);
  });
});

describe('ipToString', () => {
  test('convertit un entier en IP', () => {
    assert.equal(ipToString(3232235786), '192.168.1.10');
    assert.equal(ipToString(0), '0.0.0.0');
    assert.equal(ipToString(4294967295), '255.255.255.255');
  });

  test('aller-retour avec parseIp', () => {
    for (const ip of ['10.0.0.1', '172.16.5.130', '8.8.8.8']) {
      assert.equal(ipToString(parseIp(ip)), ip);
    }
  });

  test('refuse les entiers hors limites', () => {
    assert.throws(() => ipToString(-1));
    assert.throws(() => ipToString(2 ** 32));
    assert.throws(() => ipToString(1.5));
  });
});

describe('prefixToMask', () => {
  test('convertit un préfixe en masque', () => {
    assert.equal(prefixToMask(0), 0);
    assert.equal(prefixToMask(24), parseIp('255.255.255.0'));
    assert.equal(prefixToMask(27), parseIp('255.255.255.224'));
    assert.equal(prefixToMask(32), 4294967295);
  });

  test('refuse les préfixes invalides', () => {
    assert.throws(() => prefixToMask(-1));
    assert.throws(() => prefixToMask(33));
    assert.throws(() => prefixToMask(2.5));
  });
});

describe('maskToPrefix', () => {
  test('convertit un masque en préfixe', () => {
    assert.equal(maskToPrefix(parseIp('255.255.255.224')), 27);
    assert.equal(maskToPrefix(0), 0);
    assert.equal(maskToPrefix(parseIp('255.255.255.255')), 32);
  });

  test('refuse ce qui n’est pas un entier 32 bits non signé', () => {
    for (const valeur of [-1, 2 ** 32, 1.5, '255.255.255.0']) {
      assert.throws(() => maskToPrefix(valeur), /Masque invalide/);
    }
  });

  test('refuse les masques non contigus', () => {
    assert.throws(() => maskToPrefix(parseIp('255.0.255.0')));
    assert.throws(() => maskToPrefix(parseIp('255.255.255.1')));
  });
});

describe('parseCidr', () => {
  test('accepte la notation /préfixe', () => {
    assert.deepEqual(parseCidr('192.168.1.37/27'), { ip: parseIp('192.168.1.37'), prefix: 27 });
  });

  test('accepte la notation IP + masque, avec le même résultat', () => {
    assert.deepEqual(parseCidr('192.168.1.37 255.255.255.224'), parseCidr('192.168.1.37/27'));
  });

  test('refuse les entrées invalides', () => {
    assert.throws(() => parseCidr('192.168.1.37/33'));
    assert.throws(() => parseCidr('192.168.1.37'));
    assert.throws(() => parseCidr('192.168.1.37 255.0.255.0'));
  });

  test('refuse ce qui n’est pas du texte', () => {
    assert.throws(() => parseCidr(42), TypeError);
    assert.throws(() => parseCidr(null), TypeError);
  });

  test('refuse un préfixe mal écrit', () => {
    assert.throws(() => parseCidr('10.0.0.0/8/8'), /un seul « \/ »/);
    for (const texte of ['10.0.0.0/', '10.0.0.0/abc', '10.0.0.0/-8', '10.0.0.0/008', '10.0.0.0/ 8']) {
      assert.throws(() => parseCidr(texte), /Préfixe invalide/, texte);
    }
  });
});

describe('analyze', () => {
  // Petit raccourci : analyse à partir d'un texte « IP/préfixe ».
  const analyser = (texte) => {
    const { ip, prefix } = parseCidr(texte);
    return analyze(ip, prefix);
  };

  test('192.168.1.10/24', () => {
    const r = analyser('192.168.1.10/24');
    assert.equal(r.network, '192.168.1.0');
    assert.equal(r.broadcast, '192.168.1.255');
    assert.equal(r.mask, '255.255.255.0');
    assert.equal(r.wildcard, '0.0.0.255');
    assert.equal(r.firstHost, '192.168.1.1');
    assert.equal(r.lastHost, '192.168.1.254');
    assert.equal(r.hosts, 254);
    assert.equal(r.type, 'private');
  });

  test('172.16.5.130/26', () => {
    const r = analyser('172.16.5.130/26');
    assert.equal(r.network, '172.16.5.128');
    assert.equal(r.broadcast, '172.16.5.191');
    assert.equal(r.mask, '255.255.255.192');
    assert.equal(r.firstHost, '172.16.5.129');
    assert.equal(r.lastHost, '172.16.5.190');
    assert.equal(r.hosts, 62);
  });

  test('10.0.0.1/8', () => {
    const r = analyser('10.0.0.1/8');
    assert.equal(r.network, '10.0.0.0');
    assert.equal(r.broadcast, '10.255.255.255');
    assert.equal(r.wildcard, '0.255.255.255');
    assert.equal(r.firstHost, '10.0.0.1');
    assert.equal(r.lastHost, '10.255.255.254');
    assert.equal(r.hosts, 16777214);
  });

  test('192.168.1.37/27 : masque, wildcard et binaire', () => {
    const r = analyser('192.168.1.37/27');
    assert.equal(r.network, '192.168.1.32');
    assert.equal(r.broadcast, '192.168.1.63');
    assert.equal(r.mask, '255.255.255.224');
    assert.equal(r.wildcard, '0.0.0.31');
    assert.equal(r.firstHost, '192.168.1.33');
    assert.equal(r.lastHost, '192.168.1.62');
    assert.equal(r.hosts, 30);
    assert.equal(r.binary, '11000000.10101000.00000001.00100101');
  });

  test('cas limite /0 : tout l’espace IPv4', () => {
    const r = analyser('1.2.3.4/0');
    assert.equal(r.network, '0.0.0.0');
    assert.equal(r.broadcast, '255.255.255.255');
    assert.equal(r.mask, '0.0.0.0');
    assert.equal(r.firstHost, '0.0.0.1');
    assert.equal(r.lastHost, '255.255.255.254');
    assert.equal(r.hosts, 4294967294);
  });

  test('cas limite /31 : point à point (RFC 3021)', () => {
    const r = analyser('10.0.0.1/31');
    assert.equal(r.network, '10.0.0.0');
    assert.equal(r.broadcast, '10.0.0.1');
    assert.equal(r.firstHost, '10.0.0.0');
    assert.equal(r.lastHost, '10.0.0.1');
    assert.equal(r.hosts, 2);
  });

  test('cas limite /32 : un seul hôte', () => {
    const r = analyser('8.8.8.8/32');
    assert.equal(r.network, '8.8.8.8');
    assert.equal(r.broadcast, '8.8.8.8');
    assert.equal(r.firstHost, '8.8.8.8');
    assert.equal(r.lastHost, '8.8.8.8');
    assert.equal(r.hosts, 1);
  });

  test('refuse un préfixe ou une IP invalide', () => {
    assert.throws(() => analyze(parseIp('10.0.0.1'), 33));
    assert.throws(() => analyze(-1, 24));
  });
});

describe('addressType', () => {
  const cas = {
    '192.168.0.1': 'private',
    '10.20.30.40': 'private',
    '172.31.255.255': 'private',
    '172.32.0.1': 'public', // juste après 172.16.0.0/12
    '8.8.8.8': 'public',
    '127.0.0.1': 'loopback',
    '169.254.1.1': 'link-local',
    '224.0.0.5': 'multicast',
    '240.0.0.1': 'reserved',
    '255.255.255.255': 'reserved',
  };
  for (const [ip, type] of Object.entries(cas)) {
    test(`${ip} est ${type}`, () => {
      assert.equal(addressType(parseIp(ip)), type);
    });
  }
});
