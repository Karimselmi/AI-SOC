# Améliorations proposées au cahier des charges

Document à intégrer à la version finale du cahier des charges (sections concernées indiquées).

| Section | Cahier actuel | Amélioration | Justification |
|---|---|---|---|
| 4.2 étape 1 | Alertes récupérées depuis l'interface ou l'API de Wazuh | Récupération via le Wazuh Indexer (index wazuh-alerts-*, port 9200, API scroll). Mode hors ligne avec alerts.json | L'API REST du manager ne stocke pas l'historique des alertes, l'indexer oui |
| 3.3 | Suricata vers Wazuh via EVE JSON | Ajout de règles Suricata locales (scan de ports sur ports non utilisés, payloads SQLi/XSS vers DVWA) | Les règles par défaut ne détectent pas toujours un scan SYN simple, et la détection web dépend des règles configurées |
| 4.2 étape 3 | Caractéristiques : nombre, fréquence, ports | Fenêtres de 60 s par adresse IP source avec 12 caractéristiques : n_events, events_per_sec, n_rules, n_sig, max_level, mean_level, n_ports, n_agents, n_ssh, n_scan, n_web, n_network | Rend l'unité d'analyse précise et reproductible |
| 4.4 | Données générées dans le laboratoire | Protocole en trois phases : baseline normale de 60 min, au moins 6 exécutions par scénario, fichier experiments.csv (scénario, début, fin, IP attaquante en UTC) | Étiquetage fiable et évaluation sérieuse |
| 4.4 | Aucun dataset externe | CIC-IDS2017 reste optionnel, utilisable seulement pour des essais préliminaires du modèle. Ses caractéristiques (flux réseau) diffèrent de celles des alertes Wazuh, aucune comparaison directe | Évite une évaluation trompeuse |
| 4.3.1 | Isolation Forest | Entraîné uniquement sur 70 % des fenêtres normales (ordre chronologique), testé sur le reste et sur toutes les attaques. Analyse de sensibilité du paramètre contamination | Évite les fuites de données |
| 4.3.2 | Random Forest facultatif | Séparation par groupes (une exécution d'attaque n'est jamais à la fois en entraînement et en test) | Les fenêtres d'une même attaque sont fortement corrélées |
| 4.5 | Corrélation par IP, cible, proximité temporelle | Fusion des fenêtres anormales d'une même IP séparées de moins de 120 s, détection de séquences multi-étapes (scan puis SSH puis web), ajout des alertes hôte sans IP sur le même agent, correspondance MITRE ATT&CK issue des règles Wazuh | Fiche d'incident plus complète et justifiée |
| 4.6 | Niveau de risque estimé | Score 0 à 100 : niveau maximal des règles (40 %), score d'anomalie (30 %), volume d'alertes (20 %), séquence multi-étapes (10 %). Classes low, medium, high, critical | Priorisation explicite et discutable |
| 5.2 | Precision, recall, F1, faux positifs, temps d'analyse | Métriques par scénario, matrice de confusion, temps d'analyse mesuré par le code, jeu de test indépendant (seconde campagne), présentation des limites | Évaluation plus rigoureuse |
| 6.3 | Livrables | Ajout de experiments.csv, tests automatisés (pytest), scripts d'installation reproductibles, tableau de bord Streamlit facultatif | Reproductibilité |
| 6.4 (nouveau) | Aucune répartition | Répartition en quatre rôles : plateforme (Rebai), capteurs et scénarios (Benzarti), données et ML (Jarboui), corrélation, rapport et livraison (Selmi). Détail dans TEAM_PLAN.md | Responsabilités claires |
| 6.2 | Contraintes | Ajout : réseau host-only uniquement, aucune réponse active automatique, mots de passe de laboratoire changés avant toute exposition, horloges des VM synchronisées | Sécurité et cohérence des horodatages |
| 6.5 (nouveau) | Risques | Voir tableau ci-dessous | Anticipation |

## Risques et parades

| Risque | Parade |
|---|---|
| Peu d'alertes pour le scan | Règle Suricata locale 1000001, vérification dès la semaine 1 |
| Ressources insuffisantes pour les VM | Wazuh sur l'hôte avec Docker, deux VM seulement |
| Données insuffisantes pour Random Forest | Garder Isolation Forest comme modèle principal, Random Forest facultatif |
| Horloges désynchronisées | chrony ou additions invités, contrôle avant chaque campagne |
| Retard de l'infrastructure | L'agent est développé en parallèle avec les données synthétiques (soc_agent collect --synthetic) |
| Faux positifs élevés | Réglage de contamination, fenêtres et caractéristiques, rapport d'erreurs |
