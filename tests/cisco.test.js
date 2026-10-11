// Tests du générateur de configurations Cisco (js/cisco.js). Lancer avec : npm test
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { planVlsm } from '../js/vlsm.js';
import {
  genererConfigurations,
  depuisPlanVlsm,
  nomVlanDepuis,
  MARQUEUR,
  PORTS_SWITCH,
  VLANS_MAX,
  DEFAUTS,
} from '../js/cisco.js';

const lireFixture = (nom) => readFileSync(new URL(`fixtures/${nom}`, import.meta.url), 'utf8');

/* ---------- Scénario de référence : siège d'une entreprise, 192.168.10.0/24 ---------- */

// Besoins 100 / 50 / 20 hôtes → /25, /26, /27, qui deviennent les VLAN 10, 20 et 30.
const PLAN = planVlsm('192.168.10.0/24', [
  { nom: 'Bureautique', hotes: 100 },
  { nom: 'Serveurs', hotes: 50 },
  { nom: 'Wi-Fi invités', hotes: 20 },
]);
const CHOIX = [
  { id: 10, ports: 'Fa0/1-12' },
  { id: 20, ports: 'Fa0/13-18' },
  { id: 30, ports: 'Fa0/19-22' },
];

// Renvoie une entrée neuve à chaque appel : un test peut la modifier sans gêner les autres.
// Le natif (99), le parking (999), Port Security, le domaine et la bannière gardent leurs valeurs par défaut.
function entreeReference() {
  return {
    switch: { hostname: 'SW-SIEGE', trunk: 'Gi0/1' },
    routeur: { hostname: 'R-SIEGE' },
    vlans: depuisPlanVlsm(PLAN, CHOIX),
    // Le management prend le haut de l'espace libre laissé par le plan (192.168.10.224/27).
    management: { id: 90, reseau: '192.168.10.224/28' },
    dns: '1.1.1.1',
  };
}

// Génère la configuration après avoir appliqué « modifier » à une entrée de référence.
function generer(modifier = () => {}) {
  const entree = entreeReference();
  modifier(entree);
  return genererConfigurations(entree);
}

// Vérifie qu'une modification de l'entrée est refusée avec le message attendu.
function refuse(modifier, message) {
  assert.throws(() => generer(modifier), message);
}

describe('scénario de référence (non-régression)', () => {
  const config = generer();

  test('le switch correspond exactement à tests/fixtures/switch-reference.txt', () => {
    assert.equal(config.switch, lireFixture('switch-reference.txt'));
  });

  test('le routeur correspond exactement à tests/fixtures/routeur-reference.txt', () => {
    assert.equal(config.routeur, lireFixture('routeur-reference.txt'));
  });

  test('les blocs du switch sont dans l’ordre demandé', () => {
    const reperes = [
      'no ip domain-lookup',
      'vlan 10',
      'switchport port-security',
      'switchport mode trunk',
      'switchport access vlan 999',
      'spanning-tree mode rapid-pvst',
      'interface Vlan90',
      'ip default-gateway',
    ];
    const positions = reperes.map((repere) => config.switch.indexOf(repere));
    assert.ok(positions.every((p) => p !== -1), 'repère absent');
    assert.deepEqual(positions, [...positions].sort((a, b) => a - b));
  });

  test('aucun secret en clair : chaque « secret » est suivi du marqueur', () => {
    for (const texte of [config.switch, config.routeur]) {
      // On ignore les commentaires (lignes « ! »).
      const commandes = texte.split('\n').filter((ligne) => !ligne.startsWith('!'));
      // « secret » ou « password » suivis d'un espace : la valeur vient juste après (« password-encryption » n'en est pas une).
      const avecSecret = commandes.filter((ligne) => /\b(secret|password)\s/.test(ligne));
      assert.deepEqual(avecSecret, [`enable secret ${MARQUEUR}`, `username ${MARQUEUR} secret ${MARQUEUR}`]);
    }
  });

  test('le VLAN parking n’est pas autorisé sur le trunk', () => {
    assert.match(config.switch, /^ switchport trunk allowed vlan 10,20,30,90,99$/m);
  });

  test('le management prend la dernière adresse utilisable, la passerelle la première', () => {
    assert.match(config.switch, /^ ip address 192\.168\.10\.238 255\.255\.255\.240$/m);
    assert.match(config.switch, /^ip default-gateway 192\.168\.10\.225$/m);
  });
});

describe('options', () => {
  test('VLAN natif et parking personnalisés', () => {
    const { switch: sw, routeur } = generer((e) => {
      e.vlanNatif = { id: 98, nom: 'NATIF' };
      e.vlanParking = { id: 4000, nom: 'NOIR' };
    });
    assert.match(sw, /^ switchport trunk native vlan 98$/m);
    assert.match(sw, /^ switchport access vlan 4000$/m);
    assert.match(routeur, /^ encapsulation dot1Q 98 native$/m);
  });

  test('Port Security : maximum, violation et sticky sont repris', () => {
    const { switch: sw } = generer((e) => {
      e.portSecurity = { maximum: 1, violation: 'restrict', sticky: false };
    });
    assert.match(sw, /^ switchport port-security maximum 1$/m);
    assert.match(sw, /^ switchport port-security violation restrict$/m);
    assert.doesNotMatch(sw, /mac-address sticky/);
  });

  test('bannière, domaine et passerelle personnalisés', () => {
    const { switch: sw, routeur } = generer((e) => {
      e.banniere = 'Acces interdit ! Contact : support@entreprise.lan (poste 42).';
      e.domaine = 'siege.entreprise.lan';
      e.vlans[0].passerelle = '192.168.10.126';
    });
    assert.match(sw, /^banner motd #Acces interdit ! Contact : support@entreprise\.lan \(poste 42\)\.#$/m);
    assert.match(sw, /^ip domain-name siege\.entreprise\.lan$/m);
    assert.match(routeur, /^ip dhcp excluded-address 192\.168\.10\.126$/m);
  });

  test('ports : port seul, espaces autour du tiret, minuscules', () => {
    const { switch: sw } = generer((e) => {
      e.vlans[0].ports = 'fa0/1 - 12';
      e.vlans[2].ports = 'Gi0/2';
    });
    assert.match(sw, /^interface range FastEthernet0\/1 - 12$/m);
    assert.match(sw, /^interface GigabitEthernet0\/2\n description VLAN 30/m);
    // Ports libres : Fa0/19 à Fa0/24, d'un seul tenant.
    assert.match(sw, /^interface range FastEthernet0\/19 - 24\n description Port inutilise$/m);
  });

  test('tous les ports utilisés : aucun port à couper', () => {
    const { switch: sw } = generer((e) => {
      e.vlans[2].ports = 'Fa0/19-24';
      e.switch.trunk = 'Gi0/2';
      e.vlans.push({ id: 40, nom: 'Imprimantes', reseau: '192.168.10.240/29', ports: 'Gi0/1' });
    });
    assert.match(sw, /^! Aucun port inutilise\.$/m);
    assert.doesNotMatch(sw, /switchport access vlan 999/);
  });

  test('bornes acceptées : VLAN 2 et 4094, hostname de 63, nom de VLAN de 32, bannière de 200', () => {
    assert.doesNotThrow(() =>
      generer((e) => {
        e.vlans[0].id = 2;
        e.vlans[1].id = 4094;
        e.switch.hostname = `S${'w'.repeat(62)}`;
        e.vlans[2].nom = 'n'.repeat(32);
        e.banniere = 'b'.repeat(200);
      }),
    );
  });

  test('valeurs par défaut exposées', () => {
    assert.deepEqual(DEFAUTS.vlanNatif, { id: 99, nom: 'NATIVE' });
    assert.equal(DEFAUTS.vlanParking.id, 999);
    assert.equal(PORTS_SWITCH.length, 26);
    assert.deepEqual(PORTS_SWITCH.slice(-3), ['Fa0/24', 'Gi0/1', 'Gi0/2']);
  });
});

describe('depuisPlanVlsm', () => {
  test('reprend le sous-réseau, la passerelle et dérive le nom', () => {
    assert.deepEqual(depuisPlanVlsm(PLAN, CHOIX)[2], {
      id: 30,
      nom: 'Wi-Fi_invites',
      reseau: '192.168.10.192/27',
      passerelle: '192.168.10.193',
      ports: 'Fa0/19-22',
    });
  });

  test('null laisse un sous-réseau de côté (ex. lien WAN)', () => {
    const plan = planVlsm('10.0.0.0/24', [{ nom: 'Postes', hotes: 50 }, { nom: 'Lien WAN', hotes: 2 }]);
    const vlans = depuisPlanVlsm(plan, [{ id: 10, ports: 'Fa0/1-24' }, null]);
    assert.deepEqual(vlans.map((v) => v.nom), ['Postes']);
  });

  test('refuse un nombre de choix différent du nombre de sous-réseaux', () => {
    assert.throws(() => depuisPlanVlsm(PLAN, CHOIX.slice(0, 2)), /il en faut un par sous-réseau du plan \(3 attendus\)/);
    assert.throws(() => depuisPlanVlsm({}, CHOIX), /Plan VLSM invalide/);
    assert.throws(() => depuisPlanVlsm(PLAN, [1, 2, 3]), /Choix n°1/);
  });

  test('nom dérivé : sans accent, « _ » pour les espaces, 32 caractères au plus', () => {
    const cas = {
      'Wi-Fi invités': 'Wi-Fi_invites',
      '  Salle   de réunion  ': 'Salle_de_reunion',
      'Cœur de réseau': 'Coeur_de_reseau',
      '📡 Antennes': 'Antennes',
      'Baie B12/3 (étage 2)': 'Baie_B123_etage_2',
      'Bureau\nenable secret 0 x': 'Bureau_enable_secret_0_x',
      [`Comptabilité ${'x'.repeat(40)}`]: `Comptabilite_${'x'.repeat(19)}`,
    };
    for (const [nom, attendu] of Object.entries(cas)) assert.equal(nomVlanDepuis(nom), attendu, nom);
  });

  test('nom fait seulement de symboles : on se rabat sur VLANxx', () => {
    const plan = planVlsm('10.0.0.0/24', [{ nom: '📡📡', hotes: 10 }]);
    assert.equal(depuisPlanVlsm(plan, [{ id: 50, ports: 'Fa0/1' }])[0].nom, 'VLAN50');
  });
});

describe('erreurs : hostname', () => {
  test('vide, absent, ne commence pas par une lettre', () => {
    refuse((e) => (e.switch.hostname = ''), /^Error: Hostname du switch : le texte est vide\.$/);
    refuse((e) => delete e.routeur.hostname, /Hostname du routeur : un texte est attendu/);
    refuse((e) => (e.switch.hostname = '1SW'), /premier caractère doit être une lettre/);
    refuse((e) => (e.switch.hostname = '-SW'), /premier caractère doit être une lettre/);
  });

  test('64 caractères refusés', () => {
    refuse((e) => (e.switch.hostname = `S${'w'.repeat(63)}`), /63 caractères au maximum \(64 saisis\)/);
  });

  test('caractères hors liste blanche', () => {
    refuse((e) => (e.switch.hostname = 'SW SIEGE'), /l’espace n’est pas autorisé/);
    refuse((e) => (e.switch.hostname = 'SW_SIEGE'), /le caractère « _ » n’est pas autorisé/);
    refuse((e) => (e.switch.hostname = 'Siège'), /le caractère « è » n’est pas autorisé/);
  });

  test('switch et routeur doivent avoir des hostnames différents', () => {
    refuse((e) => (e.routeur.hostname = 'sw-siege'), /différent de celui du switch/);
  });
});

describe('erreurs : VLAN', () => {
  test('identifiant hors de 2 à 4094 ou non entier', () => {
    for (const id of [1, 0, 4095, -10]) refuse((e) => (e.vlans[0].id = id), /hors limites, de 2 à 4094/);
    for (const id of [2.5, '10', undefined, NaN]) refuse((e) => (e.vlans[0].id = id), /un nombre entier de 2 à 4094/);
  });

  test('identifiants 1002 à 1005 réservés', () => {
    for (const id of [1002, 1003, 1004, 1005]) refuse((e) => (e.vlans[1].id = id), /1002 à 1005 sont réservés/);
  });

  test('doublons d’identifiant, y compris avec natif, parking et management', () => {
    refuse((e) => (e.vlans[1].id = 10), /Identifiant du VLAN n°2 : 10 est déjà pris par le VLAN n°1\./);
    refuse((e) => (e.vlans[0].id = 99), /Identifiant du VLAN n°1 : 99 est déjà pris par le VLAN natif\./);
    refuse((e) => (e.vlans[0].id = 999), /déjà pris par le VLAN parking/);
    refuse((e) => (e.vlans[0].id = 90), /déjà pris par le VLAN de management/);
    refuse((e) => (e.vlanParking = { id: 99 }), /Identifiant du VLAN parking : 99 est déjà pris par le VLAN natif/);
  });

  test('nom : vide, 33 caractères, caractères interdits, doublon', () => {
    refuse((e) => (e.vlans[0].nom = ''), /Nom du VLAN n°1 : le texte est vide/);
    refuse((e) => (e.vlans[0].nom = 'n'.repeat(33)), /32 caractères au maximum \(33 saisis\)/);
    refuse((e) => (e.vlans[0].nom = 'Salle réunion'), /l’espace n’est pas autorisé/);
    refuse((e) => (e.vlans[0].nom = 'Réunion'), /le caractère « é »/);
    refuse((e) => (e.vlans[1].nom = 'BUREAUTIQUE'), /« BUREAUTIQUE » est déjà pris par le VLAN n°1/);
    refuse((e) => (e.vlanNatif = { id: 98, nom: 'Serveurs' }), /Nom du VLAN n°2 : « Serveurs » est déjà pris par le VLAN natif/);
  });

  test('liste vide ou trop longue', () => {
    refuse((e) => (e.vlans = []), /Aucun VLAN/);
    refuse((e) => delete e.vlans, /Aucun VLAN/);
    refuse((e) => (e.vlans = Array.from({ length: VLANS_MAX + 1 }, () => e.vlans[0])), /Trop de VLAN : 25 au maximum/);
  });

  test('management absent', () => {
    refuse((e) => delete e.management, /VLAN de management manquant/);
  });
});

describe('erreurs : sous-réseaux et adresses', () => {
  test('sous-réseau mal aligné : propose la bonne adresse', () => {
    refuse((e) => (e.vlans[1].reseau = '192.168.10.130/26'), /Voulais-tu dire 192\.168\.10\.128\/26 \?/);
  });

  test('préfixe hors de /8 à /30', () => {
    refuse((e) => (e.management.reseau = '192.168.10.236/31'), /préfixe \/31 refusé/);
    refuse((e) => (e.vlans[0].reseau = '10.0.0.0/7'), /préfixe \/7 refusé/);
  });

  test('adresse illisible', () => {
    refuse((e) => (e.vlans[0].reseau = '192.168.300.0/24'), /Sous-réseau du VLAN n°1 : IP invalide/);
    refuse((e) => (e.vlans[0].reseau = 42), /un texte comme « 192\.168\.10\.0\/25 » est attendu/);
  });

  test('sous-réseaux qui se chevauchent', () => {
    refuse(
      (e) => {
        e.vlans[1].reseau = '192.168.10.64/26';
        // Sans passerelle, la première adresse utilisable (.65) est prise : seul le chevauchement est en cause.
        delete e.vlans[1].passerelle;
      },
      /Sous-réseau du VLAN n°2 : 192\.168\.10\.64\/26 chevauche celui du VLAN n°1 \(192\.168\.10\.0\/25\)/,
    );
    refuse((e) => (e.management.reseau = '192.168.10.192/28'), /VLAN de management : .* chevauche celui du VLAN n°3/);
  });

  test('passerelle hors du sous-réseau, adresse réseau ou broadcast', () => {
    for (const passerelle of ['192.168.10.200', '192.168.10.0', '192.168.10.127']) {
      refuse((e) => (e.vlans[0].passerelle = passerelle), /n'est pas une adresse utilisable de 192\.168\.10\.0\/25/);
    }
    refuse((e) => (e.vlans[0].passerelle = '192.168.10'), /Passerelle du VLAN n°1 : IP invalide/);
  });

  test('passerelle du management égale à l’adresse du switch', () => {
    refuse((e) => (e.management.passerelle = '192.168.10.238'), /est l'adresse du switch/);
  });

  test('DNS absent, illisible ou impossible', () => {
    refuse((e) => delete e.dns, /Serveur DNS : une adresse IP est attendue/);
    refuse((e) => (e.dns = '1.1.1'), /Serveur DNS : IP invalide/);
    for (const dns of ['127.0.0.1', '224.0.0.1', '0.0.0.0', '255.255.255.255', '169.254.1.1']) {
      refuse((e) => (e.dns = dns), /pas celle d'un serveur/);
    }
  });

  test('domaine mal formé', () => {
    for (const domaine of ['entreprise..lan', '-entreprise.lan', 'entreprise.lan.', 'entreprise_lan']) {
      refuse((e) => (e.domaine = domaine), /^Error: Domaine : /);
    }
  });
});

describe('erreurs : ports', () => {
  test('ports qui n’existent pas sur le 2960-24TT', () => {
    refuse((e) => (e.vlans[2].ports = 'Fa0/19-25'), /le port Fa0\/25 n'existe pas sur un 2960-24TT \(Fa0\/1 à Fa0\/24\)/);
    refuse((e) => (e.vlans[2].ports = 'Gi0/3'), /le port Gi0\/3 n'existe pas/);
    for (const ports of ['Fa0/0', 'Fa1/1', 'Eth0/1', 'Fa0/01', 'FastEthernet0/1', 'Fa0/1-Gi0/2', 'Fa0/1,Fa0/3', '']) {
      refuse((e) => (e.vlans[2].ports = ports), /n'est pas une plage valide/);
    }
  });

  test('plage à l’envers', () => {
    refuse((e) => (e.vlans[0].ports = 'Fa0/12-1'), /à l'envers, écris Fa0\/1-12/);
  });

  test('chevauchement entre VLAN ou avec le trunk', () => {
    refuse((e) => (e.vlans[1].ports = 'Fa0/12-18'), /Ports du VLAN n°2 : Fa0\/12 est déjà pris par le VLAN n°1\./);
    refuse((e) => (e.vlans[2].ports = 'Gi0/1-2'), /Gi0\/1 est déjà pris par le port trunk/);
  });

  test('port trunk inexistant ou multiple', () => {
    refuse((e) => (e.switch.trunk = 'Gi0/3'), /Port trunk : le port Gi0\/3 n'existe pas/);
    refuse((e) => (e.switch.trunk = 'Gi0/1-2'), /un seul port est attendu/);
  });
});

describe('erreurs : Port Security et bannière', () => {
  test('maximum hors de 1 à 64', () => {
    for (const maximum of [0, 65, 1.5, 'deux']) {
      refuse((e) => (e.portSecurity = { maximum }), /le maximum doit être un nombre entier de 1 à 64/);
    }
  });

  test('violation inconnue, sticky non booléen', () => {
    refuse((e) => (e.portSecurity = { violation: 'drop' }), /mode de violation « drop » inconnu/);
    refuse((e) => (e.portSecurity = { violation: 'Shutdown' }), /inconnu/);
    refuse((e) => (e.portSecurity = { sticky: 'oui' }), /sticky doit valoir true/);
  });

  test('bannière : vide, 201 caractères, accents, point d’interrogation', () => {
    refuse((e) => (e.banniere = ''), /Bannière : le texte est vide/);
    refuse((e) => (e.banniere = 'b'.repeat(201)), /200 caractères au maximum \(201 saisis\)/);
    refuse((e) => (e.banniere = 'Accès réservé'), /le caractère « è »/);
    refuse((e) => (e.banniere = 'Qui est la ?'), /le caractère « \? »/);
  });
});

describe('tentatives d’injection de commandes', () => {
  // Chaque tentative glisse une commande pirate dans un champ texte. Toutes doivent être refusées.
  const tentatives = {
    'hostname avec retour à la ligne': (e) => (e.switch.hostname = 'SW1\nusername pirate privilege 15 secret 0 x'),
    'hostname avec retour à la ligne final': (e) => (e.switch.hostname = 'SW1\n'),
    'hostname avec retour chariot': (e) => (e.routeur.hostname = 'R1\rno ip ssh version 2'),
    'hostname avec « ! »': (e) => (e.switch.hostname = 'SW1!'),
    'nom de VLAN avec retour à la ligne': (e) => (e.vlans[0].nom = 'Bureau\ninterface Vlan1'),
    'nom de VLAN commençant par « ! »': (e) => (e.vlans[0].nom = '!Bureau'),
    'nom de VLAN avec séparateur de ligne Unicode U+2028': (e) => (e.vlans[0].nom = 'Bureau\u2028shutdown'),
    'nom de VLAN avec fin de ligne Unicode U+0085': (e) => (e.vlans[0].nom = 'Bureau\u0085shutdown'),
    'nom de VLAN avec caractère nul': (e) => (e.vlans[0].nom = 'Bureau\u0000'),
    'nom de VLAN avec échappement de terminal': (e) => (e.vlans[0].nom = 'Bureau\u001B[2J'),
    'nom de VLAN avec tabulation': (e) => (e.vlans[0].nom = 'Bureau\tx'),
    'nom de VLAN avec inversion du sens du texte U+202E': (e) => (e.vlans[0].nom = 'Bureau\u202Eexe'),
    'nom du VLAN natif avec retour à la ligne': (e) => (e.vlanNatif = { id: 99, nom: 'NATIVE\nvlan 1' }),
    'domaine avec retour à la ligne': (e) => (e.domaine = 'entreprise.lan\nip http server'),
    'bannière avec délimiteur puis commande': (e) => (e.banniere = 'Bienvenue#\nusername pirate secret 0 x'),
    'bannière qui se ferme avec le délimiteur': (e) => (e.banniere = 'Bienvenue# enable secret 0 x'),
    'bannière avec retour à la ligne': (e) => (e.banniere = 'Bienvenue\nenable secret 0 x'),
    'bannière avec caractère de contrôle (Ctrl+C)': (e) => (e.banniere = 'Bienvenue\u0003'),
    'plage de ports avec retour à la ligne': (e) => (e.vlans[0].ports = 'Fa0/1-12\nshutdown'),
    'port trunk avec retour à la ligne': (e) => (e.switch.trunk = 'Gi0/1\nno switchport'),
    'sous-réseau avec retour à la ligne': (e) => (e.vlans[0].reseau = '192.168.10.0/25\nip http server'),
    'passerelle avec retour à la ligne': (e) => (e.vlans[0].passerelle = '192.168.10.1\nip http server'),
    'DNS avec retour à la ligne': (e) => (e.dns = '1.1.1.1\nip http server'),
    'violation avec retour à la ligne': (e) => (e.portSecurity = { violation: 'shutdown\nno spanning-tree' }),
  };
  for (const [description, modifier] of Object.entries(tentatives)) {
    test(`refuse : ${description}`, () => assert.throws(() => generer(modifier)));
  }

  test('le message d’erreur nomme le caractère invisible sans le recopier', () => {
    assert.throws(
      () => generer((e) => (e.vlans[0].nom = 'Bureau\nenable')),
      (erreur) => !erreur.message.includes('\n') && erreur.message.includes('le retour à la ligne (U+000A)'),
    );
    assert.throws(
      () => generer((e) => (e.vlans[0].nom = 'Bureau\u202Eexe')),
      (erreur) => !erreur.message.includes('\u202E') && erreur.message.includes('U+202E'),
    );
  });

  test('un délimiteur dans la bannière a son propre message', () => {
    refuse((e) => (e.banniere = 'Batiment #2'), /le caractère « # » est interdit, il marque le début et la fin/);
  });

  test('une entrée qui n’est pas un objet est refusée', () => {
    for (const entree of [null, undefined, 'SW1', 42]) {
      assert.throws(() => genererConfigurations(entree), /Entrée invalide/);
    }
  });
});
