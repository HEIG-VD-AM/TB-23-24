# Externalisation des clefs privées WireGuard sur des périphériques sécurisés

Dans ce repository, vous pourrez retrouver l'ensemble des documents et codes produits pour la réalisation de mon travail de Bachelor à l'HEIG.
Celui-ci a été réalisé dans le cadre de la formation d'ingénieur en cybersécurité et a été supervisé par docteur et professeur Maxime Augier.

Ci-dessous, j'ai essayé de résumé la cause de ce projet, ainsi que le résultat attendu et les quelques points clés de sa réalisation.

# Résumé

Actuellement, les VPNs sont largement utilisés pour protéger les communications sensibles contre des menaces telles que l'interception de données et les attaques de type man-in-the-middle. Parmi les nombreuses solutions VPN, WireGuard se distingue par sa modernité, sa performance, sa sécurité robuste, sa rapidité et sa simplicité d'utilisation.

Le problème principal de ce travail réside dans la gestion de la clé privée de WireGuard, actuellement stockée sur le système de l’utilisateur au niveau de la mémoire, la rendant vulnérable en cas de compromission de la machine. Un attaquant pouvant extraire cette clé pourrait écouter les communications actuelles et usurper l’identité de l’utilisateur dans les sessions futures. Ce risque est un obstacle majeur à l'adoption de WireGuard dans des environnements hautement sécurisés.

Pour répondre à cette problématique, l’objectif de ce travail de Bachelor a été d’intégrer WireGuard avec des périphériques externes sécurisés afin d’externaliser la clé privée du VPN. En déplaçant la clé hors du système de l’utilisateur et en la stockant sur un périphérique sécurisé tel qu'une smartcard.

Le projet a d'abord exploré différentes implémentations et périphériques, optant finalement pour BoringTun (implémentation WireGuard en Rust) ainsi qu'une NitroKey en utilisant le protocole OpenPGP en raison de sa compatibilité et sa simplicité d’intégration. Avant de passer à l'implémentation directement sur BoringTun, il a été primordial de réaliser un programme de test. Celui-ci a démontré que l'utilisation d'une smartcard pour les opérations cryptographiques est interchangeable avec l'utilisation de la librairie cryptographique de BoringTun, validant ainsi la faisabilité de l'externalisation de la clé privée.

Les résultats de ces tests ont ensuite été transférés directement sur l'implémentation de BoringTun afn d'avoir un VPN totalement fonctionnel avec une smartcard.

On retrouve aussi, à la fin de ce travail, une suite d'objectifs optionnels dont le but était d'explorer des pistes permettant d'améliorer les performances des VPNs s'exécutant dans l'espace utilisateur de la machine. Il a donc été nécessaire, dans un premier temps, de comprendre le fonctionnement du réseau au sein des systèmes Unix, puis d'énumérer ses limitations, notamment dans le cas des interfaces TUN/TAP.

Une fois ces limitations listées, le facteur ayant un impact majeur sur la performance réside dans le changement de contexte que nécessite chaque appel système.
Lorsqu'un VPN souhaite lire ou écrire sur l'interface TUN/TAP qu'il utilise, il va souvent devoir utiliser un appel système pour chaque opération.
Or, il existe des solutions permettant d'augmenter le nombre d'opérations traitées à l'aide d'un seul appel système.

Parmi celles-ci, une solution très récente est io_uring, qui, à l'aide de files partagées entre l'espace utilisateur et l'espace noyau, permet de déposer des tâches dans celles-ci sans avoir à faire d'appel système. Puis, lorsque toutes les tâches à exécuter ont été déposées, il est possible de signaler, à l'aide d'un seul appel système, au kernel qu'il faut traiter celles-ci.

Cette dernière partie de ce travail a cherché à utiliser cette nouvelle manière de gérer les appels système pour démontrer qu'il est possible de l'appliquer aux VPNs.

# Organisation

Afin de faciliter la navigation à travers mon travail, je vous propose une brève explication pour chaque dossier/fichier.

- Défense : Contient la présentation qui a été utilisée pour la défense de ce travail.
- Documentation :
  - Affiche : Affiche grand format contenant le résumé de ce travail.
  - Mode d'emploi : Contient les quelques détails pour qu'un utilisateur en possession du programme final puisse l'utiliser.
  - Rapport : Rapport contenant tous les détails de ce travail.
- Implémentation :
  - boringtun : Contient le code de BoringTun auquel j'ai apporté des modifications afin qu'il supporte les périphériques sécurisés avec OpenPGP.
  - io_uring_poc : Comprend les quatre variantes du programme de test qui a été réalisé afin de démontrer l'amélioration des performances des VPNs.
  - openpgp_sc_poc : Code ayant permis de prouver que ce travail de Bachelor était réalisable avant d'apporter les modifications à BoringTun.
  - x25519-dalek : Version modifiée de la crate Rust `x25519-dalek` afin d'ajouter la création d'un secret partagé à partir d'un tableau de bytes.
