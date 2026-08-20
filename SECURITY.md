# Politique de sécurité

GMPilot est un outil de gestion de vulnérabilités auto-hébergé (frontend
GVM/OpenVAS). La sécurité du projet est prise au sérieux — merci de contribuer à
le garder sûr.

## Signaler une vulnérabilité

> **N'ouvrez pas d'issue publique pour une faille de sécurité.**

Utilisez le **signalement privé de GitHub** :

1. Onglet **Security** du dépôt → **Report a vulnerability**
   ([Private vulnerability reporting](https://docs.github.com/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)).
2. Décrivez la faille de façon aussi détaillée que possible.

Merci d'inclure, dans la mesure du possible :

- une description de la vulnérabilité et de son **impact** ;
- les **étapes de reproduction** (preuve de concept si possible) ;
- la **version ou le commit** concerné ;
- toute idée de correctif ou d'atténuation.

## Traitement

GMPilot est maintenu par une seule personne, en **best-effort** :

- j'accuse réception et j'évalue le rapport dès que possible ;
- je vous tiens informé·e de l'avancement directement dans l'avis privé ;
- une fois la faille corrigée, un correctif est publié.

Il n'y a **pas de SLA ferme ni de programme de bug bounty** : ce projet est
bénévole. Merci pour votre patience.

## Divulgation coordonnée

Merci de me laisser un délai raisonnable pour corriger **avant toute divulgation
publique**. La date de publication de l'avis est convenue ensemble ; l'avis est
rendu public une fois le correctif disponible.

## Crédit

Sauf demande d'anonymat de votre part, les personnes qui signalent une
vulnérabilité valide sont **créditées dans l'avis de sécurité publié**. Merci à
elles.

## Périmètre

GMPilot est **auto-hébergé** : il n'existe pas d'instance hébergée officielle.
Les rapports portent sur le code de ce dépôt — merci de ne tester que sur votre
propre instance, sans impacter de tiers.
