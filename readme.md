# Projet Réseau - Dissecteur de fichier pcap

> Ce programme java a été créé dans le cadre du module _Rappel Réseau_ à l'occasion du cursus _MS-SIS_ de l'ESIEA, promo : 2024-2025.
> 
## Objectif
L'objectif est de réaliser un programme WireSharks likes capables d'analyser les différentes trame réseau enregistrés dans un fichier pcap.

## Consignes
* Utilisation des librairies de base : ``java.io.*`` ``java.util.*`` ``java.time.*`` ... 
* Pas le droit d'utiliser ``jNetPcap``
* Protocoles à implémenter :
  * _Ethernet_
  * _ARP_
  * _IPv4_
  * _IPv6_
  * _ICMP_
  * _TCP (+follow tcp stream)_
  * _UDP_
  * _DHCP_
  * _DNS_
  * _HTTP_
  * _QUIC_
  * _FTP_

## Explications
Ce projet est un analyseur de paquets réseau qui permet de décoder et d'afficher les informations contenues dans différents protocoles de la suite TCP/IP, y compris IPv4, IPv6, TCP, UDP, ICMP, HTTP, FTP et DHCP. Le programme lit les paquets à partir d'un fichier PCAP, analyse les en-têtes des protocoles et extrait des informations pertinentes pour chaque paquet.

### Fonctionnement
1. **Ouverture du fichier PCAP** : Le programme commence par ouvrir un fichier au format PCAP. Il lit l'en-tête global (Global Header), qui contient des informations sur la capture, telles que le format de timestamp, la taille des paquets et le type de liaison de données.
2. **Lecture des record headers** : Ensuite, le programme entre dans une boucle pour lire chaque record header. Pour chaque record, il extrait les données essentielles, y compris le timestamp et la longueur du paquet.
3. **Analyse de la trame Ethernet** : Pour chaque record, le programme affiche d'abord les informations de la trame Ethernet, telles que les adresses MAC source et destination, ainsi que le type de protocole contenu dans la trame.
4. **Décodage des protocoles de couche supérieure** :
   * **IPv4** et **IPv6** : Selon le type de protocole de la trame Ethernet, le programme passe à l'analyse de l'en-tête IPv4 ou IPv6. Il extrait des informations telles que les adresses IP source et destination, la version du protocole, la taille de l'en-tête, etc.
   * **TCP** et **UDP** : Après l'analyse de l'en-tête IP, le programme analyse le protocole de transport, qu'il s'agisse de TCP ou d'UDP. Pour TCP, il extrait des données comme les ports source et destination, les numéros de séquence et d'accusé de réception, ainsi que les indicateurs de contrôle (flags). Pour UDP, il lit simplement les ports et la longueur.
   * **ICMP** : Si le paquet contient un message ICMP, le programme décode les champs de type et de code pour identifier le type de message ICMP.
   * **HTTP** et **FTP** : Lorsqu'un paquet HTTP ou FTP est détecté, le programme extrait et affiche les lignes pertinentes de la requête ou de la réponse, ce qui aide à comprendre les interactions entre le client et le serveur.
   * **DHCP** : Les paquets DHCP sont analysés pour extraire les adresses IP assignées et d'autres options DHCP pertinentes.
5. **Affichage structuré** : Les informations décodées sont présentées de manière structurée et lisible dans la console, facilitant l'examen des communications réseau. Chaque protocole est géré par sa propre classe, permettant une organisation claire et une extensibilité future.

## Execution
>java 17.0.5 2022-10-18 LTS
>Développer sur Windows
1. ``cd Projet_Reseau``
2. ``javac *.java``
3. ``java DissecteurPCAP pcaps\file_name.pcap``

Dossier de fichier pcap fournit si besoin. Nom du dossier : _pcaps_

## Exemples
![Example result](empty\example.png "Example result")

## Problèmes rencontrés
**Gestion des en-têtes d'extension dans IPv6** : La compréhension et l'implémentation correcte des en-têtes d'extension d'IPv6 ont été délicates. J'ai eu des difficultés à traiter ces en-têtes dans l'ordre approprié et à déterminer comment chaque type d'en-tête interagissait avec les autres protocoles encapsulés. Malgré la connaissance de la théorie, qui consistait à examiner la taille du champ next header ainsi que son type, puis à effectuer un saut jusqu'à l'extension suivante en fonction de ce type, il a été compliqué d'atteindre le next header indiquant le protocole de transport UDP ou TCP. Je n'ai jamais réussi à résoudre ce problème dans les temps.

**Identification correcte des protocoles** : Lors de l'analyse des paquets, il a été essentiel de s'assurer que le programme pouvait distinguer correctement les différents protocoles, notamment en vérifiant les ports de destination et en analysant les en-têtes appropriés pour chaque protocole. Par exemple, le défi consistait à identifier si un paquet était HTTP ou FTP uniquement sur la base du port, car d'autres protocoles pouvaient également utiliser le même port.

**Gestion des caractères spéciaux dans les payloads** : Lors de l'extraction des données des paquets HTTP et FTP, il a été constaté que certains payloads contenaient des caractères spéciaux et non imprimables. Malgré plusieurs recherches, je n'ai pas réussi à résoudre ce problème.

**Manque de temps** : Le manque de temps et la mauvaise organisation m'ont contraint à filtrer les protocoles à implémenter. Cela a rendu impossible l'implémentation de DNS, QUIC et du suivi des flux TCP (Follow TCP Stream).

## Pistes d'améliorations
**Meilleure gestion des en-têtes d'extension IPv6** : Il serait bénéfique d'approfondir la compréhension des en-têtes d'extension d'IPv6 et de développer une méthode plus robuste pour les traiter dans l'ordre approprié.

**Amélioration de l'identification des protocoles** : Pour améliorer la précision de l'identification des protocoles, une analyse plus fine des en-têtes pourrait être mise en place. Par exemple, l'utilisation de mécanismes de filtrage basés sur d'autres critères, tels que les valeurs spécifiques des en-têtes ou des analyses de payloads, pourrait réduire les ambiguïtés. La méthode actuelle pour l'identification de HTTP, FTP et DHCP est largement consolidable.

**Traitement des caractères spéciaux dans les payloads HTTP et FTP** : Permettre de présenter les informations de manière plus lisible et cohérente.

**Extension des protocoles supportés** : Pour une future version du projet, envisager d'ajouter le support pour des protocoles supplémentaires tels que DNS, QUIC ou le suivi des flux TCP. Cela enrichirait l'analyse des paquets et offrirait une vue plus complète des communications réseau.

**Options de filtrage pour l'affichage** : Ajouter des options de filtrage permettant à l'utilisateur de sélectionner les protocoles à afficher ou d'affiner les résultats en fonction de critères spécifiques, comme les adresses IP, les ports, ou les types de messages.

**Documentation et tests** : Créer une documentation plus détaillée concernant l'utilisation et les fonctionnalités du programme, ainsi que des tests unitaires pour assurer la robustesse du code, pourrait faciliter les futures modifications et améliorations.