#!/bin/bash

# Programme permettant de récolter le débit, ainsi que le temps de réponse moyen des tests de ping réalisés pour la partie `Performances`

TARGET="192.168.0.3"
COUNT=20000
PACKET_SIZE=1472 # Max MTU - IP header - ICMP header
INSTANCES=10

# Fonction pour exécuter un flood ping et extraire le RTT moyen
run_flood_ping() {
  local instance_id=$1
  ping -f -c $COUNT -s $PACKET_SIZE $TARGET | tail -n 1 > "ping_flood_results_$instance_id.txt" &
}

# Enregistrer le temps de début
START_TIME=$(date +%s.%N)

# Lancer les instances de flood ping en parallèle
for i in $(seq 1 $INSTANCES); do
  run_flood_ping $i
done

# Attendre que toutes les instances se terminent
wait

# Enregistrer le temps de fin
END_TIME=$(date +%s.%N)

# Calculer le temps total écoulé
ELAPSED_TIME=$(echo "$END_TIME - $START_TIME" | bc)

# Calculer la taille totale des données envoyées
TOTAL_DATA=$((COUNT * PACKET_SIZE * INSTANCES))

# Calculer le débit en octets par seconde
THROUGHPUT=$(echo "$TOTAL_DATA / $ELAPSED_TIME" | bc)

# Convertir le débit en bits par seconde
THROUGHPUT_BPS=$(echo "$THROUGHPUT * 8" | bc)

# Convertir le débit en mégabits par seconde
THROUGHPUT_MBPS=$(echo "scale=2; $THROUGHPUT_BPS / 1000000" | bc)

# Initialiser les variables pour le RTT total et le nombre de RTTs
TOTAL_RTT=0
RTT_COUNT=0

# Analyser les fichiers de résultats pour extraire le RTT moyen de chaque instance
for i in $(seq 1 $INSTANCES); do
  RTT_LINE=$(cat "ping_flood_results_$i.txt")
  AVG_RTT=$(echo $RTT_LINE | awk -F'/' '{print $5}')
  TOTAL_RTT=$(echo "$TOTAL_RTT + $AVG_RTT" | bc)
  RTT_COUNT=$((RTT_COUNT + 1))
done

# Calculer le RTT moyen global
GLOBAL_AVG_RTT=$(echo "scale=2; $TOTAL_RTT / $RTT_COUNT" | bc)

# Afficher les résultats
printf "Débit approximatif avec %d instances : %.2f Mbps\n" $INSTANCES $THROUGHPUT_MBPS
printf "RTT moyen global : %.2f ms\n" $GLOBAL_AVG_RTT

# Nettoyer les fichiers temporaires
rm ping_flood_results_*.txt
