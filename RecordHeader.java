import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

/**
 * Représente l'en-tête d'un enregistrement dans un fichier PCAP
 */
public class RecordHeader {

    private long tsSec;
    private long tsUsec;
    private int inclLen;
    private int origLen;
    private int nbFrame;

    /**
     * Constructeur
     * Lit l'en-tête d'enregistrement à partir du flux de fichier spécifié
     * @param file Flux de fichier à partir duquel lire les données
     * @param nbFrame Numéro de l'enregistrement (trame) à lire
     * @throws IOException Si une erreur d'entrée/sortie se produit lors de la lecture
     */
    public RecordHeader(FileInputStream file, int nbFrame) throws IOException {
        byte[] recordHeaderData = new byte[16];
        file.read(recordHeaderData);
        
        ByteBuffer buffer = ByteBuffer.wrap(recordHeaderData);
        buffer.order(ByteOrder.LITTLE_ENDIAN);

        this.tsSec = buffer.getInt();
        this.tsUsec = buffer.getInt();
        this.inclLen = buffer.getInt();
        this.origLen = buffer.getInt();

        this.nbFrame = nbFrame;
    }

    public int getInclLen() {
        return inclLen;
    }

    /**
     * Formate 'timestamp' en une chaîne de caractères lisible.
     * @param seconds Nombre de secondes
     * @param microseconds Nombre de microsecondes
     * @return Chaîne formatée représentant la date et l'heure
     */
    private String formatTimestamp(long seconds, long microseconds) {
        Instant timestamp = Instant.ofEpochSecond(seconds, microseconds * 1000);
        return DateTimeFormatter
            .ofPattern("yyyy-MM-dd HH:mm:ss.SSS")
            .withZone(ZoneId.systemDefault())
            .format(timestamp);
    }

    /**
     * Affiche les informations de l'en-tête d'enregistrement.
     */
    public void display() {
        if(tsSec != 0){
            System.out.println("-- Record Header --");
            System.out.println("Frame numero : " + nbFrame);
            System.out.println("Date et heure : " + formatTimestamp(tsSec, tsUsec));
            System.out.println("Longueur des octets captures : " + inclLen);
            System.out.println("Longueur originale : " + origLen);
        }
    }
}
