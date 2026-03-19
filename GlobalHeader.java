import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Représente l'en-tête global d'un fichier PCAP
 * Cet en-tête fournit des informations sur le format et les configurations utilisées
 */
public class GlobalHeader {

    private int magicNumber;
    private int versionMajor;
    private int versionMinor;
    private int thisZone;
    private int sigfigs;
    private int snaplen;
    private int network;

    /**
     * Constructeur
     * Lit l'en-tête global depuis le fichier PCAP et extrait les informations relatives
     * à la version, la longueur maximale des paquets et le type de réseau
     * @param file Le flux d'entrée du fichier PCAP
     * @throws IOException En cas d'erreur de lecture des données
     */
    public GlobalHeader(FileInputStream file) throws IOException {
        byte[] globalHeaderData = new byte[24];
        file.read(globalHeaderData);
        
        ByteBuffer buffer = ByteBuffer.wrap(globalHeaderData);
        buffer.order(ByteOrder.LITTLE_ENDIAN);

        this.magicNumber = buffer.getInt();
        this.versionMajor = buffer.getShort();
        this.versionMinor = buffer.getShort();
        this.thisZone = buffer.getInt();
        this.sigfigs = buffer.getInt();
        this.snaplen = buffer.getInt();
        this.network = buffer.getInt();
    }

    /**
     * Affiche les informations de l'en-tête global
     */
    public void display() {
        System.out.println("\n-- Global Header --");
        System.out.printf("Magic Number: 0x%08X%n", magicNumber);
        System.out.println("Version : " + versionMajor + "." + versionMinor);
        System.out.println("Correction GMT vers le temps local : " + thisZone);
        System.out.println("Précision des horodatages : " + sigfigs);
        System.out.println("Longueur max des paquets : " + snaplen + " octets");
        System.out.println("Type : " + network);
    }
}
