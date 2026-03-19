import java.io.FileInputStream;
import java.io.IOException;

/**
 * Responsable de la gestion des fichiers pcap
 */
public class PCAPFile {
    private FileInputStream file;

    /**
     * Constructeur de la classe PCAPFile
     * Ouvre le fichier PCAP spécifié pour lecture
     * @param filePath Chemin d'accès au fichier PCAP à ouvrir
     * @throws IOException Si une erreur d'entrée/sortie se produit lors de l'ouverture du fichier
     */
    public PCAPFile(String filePath) throws IOException {
        this.file = new FileInputStream(filePath);
    }

    /**
     * Lit et renvoie l'en-tête global du fichier PCAP
     * @return L'en-tête global du fichier PCAP
     * @throws IOException Si une erreur d'entrée/sortie se produit lors de la lecture
     */
    public GlobalHeader readGlobalHeader() throws IOException {
        return new GlobalHeader(file);
    }

    /**
     * Lit et renvoie un en-tête d'enregistrement à partir du fichier PCAP
     * @param nbFrame Numéro de l'enregistrement à lire
     * @return L'en-tête d'enregistrement correspondant
     * @throws IOException Si une erreur d'entrée/sortie se produit lors de la lecture
     */
    public RecordHeader readRecordHeader(int nbFrame) throws IOException {
        return new RecordHeader(file, nbFrame);
    }

    /**
     * Lit et renvoie une trame Ethernet à partir du fichier PCAP
     * @param inclLen Longueur incluse de la trame Ethernet
     * @return La trame Ethernet lue
     * @throws IOException Si une erreur d'entrée/sortie se produit lors de la lecture
     */
    public EthernetFrame readEthernetFrame(int inclLen) throws IOException {
        return new EthernetFrame(file, inclLen);
    }
}
