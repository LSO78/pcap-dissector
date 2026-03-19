import java.io.*;

/**
 * Classe principale
 * Ce programme lit et analyse les trames réseau contenues dans un fichier PCAP
 * Il extrait le Global Header, puis traite chaque Record Header et la trame Ethernet associée
 *
 * Le nom du fichier PCAP doit être spécifié en argument
 * Exemple : java DissecteurPCAP monfichier.pcap
 */
public class DissecteurPCAP {
    public static void main(String[] args) {
        try{
            // Vérifie si le nom de fichier PCAP est passé en argument
            if (args.length < 1) {
                System.err.println("Veuillez spécifier le nom du fichier PCAP en argument");
                return;
            }
            String fileName = args[0];

            // Crée un objet PCAPFile pour lire le contenu du fichier PCAP
            PCAPFile pcapFile = new PCAPFile(fileName);

            // Lit et affiche le Global Header du fichier PCAP
            GlobalHeader globalHeader = pcapFile.readGlobalHeader();
            globalHeader.display();

            int nbFrame = 1;

            while (true) {
                try {
                    // Lit le Record Header suivant et l'affiche
                    RecordHeader recordHeader = pcapFile.readRecordHeader(nbFrame);
                    recordHeader.display();

                    // Lit et affiche la trame Ethernet associée au Record Header
                    EthernetFrame ethernetFrame = pcapFile.readEthernetFrame(recordHeader.getInclLen());
                    ethernetFrame.display();

                    nbFrame++;
                } catch (Exception e) {
                    // Si une exception est levée, cela signifie qu'il n'y a plus de trames à lire, on sort de la boucle
                    break;
                }
            }
        } catch (IOException e) {
            System.err.println("Erreur : " + e.getMessage());
        }
    }
}